"""权限交接演练的端到端测试（真实 PostgreSQL）。

需要 TEST_DATABASE_URL（能 CREATE ROLE / CREATE DATABASE 的管理员连接串）。
套件会自备一个带 CREATEROLE 的专用角色与数据库，请指向一次性实例：

    TEST_DATABASE_URL=postgresql://postgres@localhost/postgres pytest tests/test_handover.py
"""

from __future__ import annotations

import importlib
import os
import re
import sys
import threading

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ADMIN_URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not ADMIN_URL, reason="TEST_DATABASE_URL not set; real-database tests skipped"
)

ROLE = "lock_drill_test"  # 与行锁测试共用同一应用角色（角色是集群级对象）
PASSWORD = "lock_drill_test"
DB = "lock_handover_test"


def _provision() -> str:
    assert ADMIN_URL
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
        try:
            conn.execute(f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PASSWORD}' CREATEROLE")
        except psycopg.errors.DuplicateObject:
            conn.execute(f"ALTER ROLE {ROLE} CREATEROLE")
        conn.execute(f"CREATE DATABASE {DB} OWNER {ROLE}")
        conn.execute(f"GRANT CREATE, USAGE ON SCHEMA public TO {ROLE}")
    parts = conninfo_to_dict(ADMIN_URL)
    parts["dbname"] = DB
    parts["user"] = ROLE
    parts["password"] = PASSWORD
    return make_conninfo(**parts)


@pytest.fixture(scope="session")
def database_url() -> str:
    return _provision()


@pytest.fixture()
def web(database_url, monkeypatch):
    """Fresh app per test; the handover drill always starts from canonical grants."""
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("BLOCK_CONFIRM_SECONDS", "5")
    for name in list(sys.modules):
        if name.startswith("app."):
            del sys.modules[name]
    import app.config
    import app.db
    import app.drill
    import app.grants
    import app.main

    importlib.reload(app.config)
    importlib.reload(app.db)
    app.drill = importlib.reload(app.drill)
    app.grants = importlib.reload(app.grants)
    app.main = importlib.reload(app.main)
    client = TestClient(app.main.app)
    with client:
        app.grants.reset_handover()
        yield client, app.grants
    app.drill.store.shutdown()


def _state(client) -> dict:
    res = client.get("/api/handover/state")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"]
    return body["state"]


def _accounts(state: dict) -> dict:
    return {a["name"]: a for a in state["accounts"]}


def _temps(state: dict) -> dict:
    return {t["id"]: t for t in state["temporary_grants"]}


def _preview(client, grant_id: str, checked) -> dict:
    res = client.post(
        "/api/handover/preview", data={"grant_id": grant_id, "checked": list(checked)}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"]
    return body["preview"]


def _confirm(client, grant_id: str, checked, fingerprint: str):
    return client.post(
        "/api/handover/confirm",
        data={
            "grant_id": grant_id,
            "fingerprint": fingerprint,
            "checked": list(checked),
        },
    )


def _try_query(client, account: str) -> dict:
    res = client.post("/api/handover/query", data={"account": account})
    assert res.status_code == 200, res.text
    return res.json()["query"]


def test_seeded_grant_chains_match_requirement(web):
    client, _grants = web
    state = _state(client)
    assert state["table"] == "public.deploy_report"
    assert state["row_count"] >= 6

    temps = _temps(state)
    assert temps["T1"]["exists"] is True
    assert temps["T1"]["grantee"] == "duty_alpha"
    assert temps["T2"]["exists"] is True
    assert temps["T2"]["grantee"] == "duty_beta"
    assert temps["T1"]["covers"] == ["report_alice", "report_bob"]
    assert temps["T2"]["covers"] == ["report_bob", "report_carol"]

    accounts = _accounts(state)
    # 有的账号只走一条授权链，有的同时走两条
    assert accounts["report_alice"]["chains"] == ["T1"]
    assert accounts["report_bob"]["chains"] == ["T1", "T2"]
    assert accounts["report_carol"]["chains"] == ["T2"]
    assert all(a["can_read"] for a in accounts.values())

    owner = state["owner"]
    edges = {
        (e["grantor"], e["grantee"], e["privilege_type"], e["is_grantable"])
        for e in state["edges"]
    }
    # T1 含两级转授：owner → duty_alpha → duty_gamma → report_*
    assert (owner, "duty_alpha", "SELECT", True) in edges
    assert ("duty_alpha", "duty_gamma", "SELECT", True) in edges
    assert ("duty_gamma", "report_alice", "SELECT", False) in edges
    assert ("duty_gamma", "report_bob", "SELECT", False) in edges
    # T2 一级转授：owner → duty_beta → report_*
    assert (owner, "duty_beta", "SELECT", True) in edges
    assert ("duty_beta", "report_bob", "SELECT", False) in edges
    assert ("duty_beta", "report_carol", "SELECT", False) in edges


def test_preview_lists_losing_and_regrant_without_touching_db(web):
    client, _grants = web
    before = _state(client)

    preview = _preview(client, "T1", ["report_alice", "report_bob"])
    assert preview["losing"] == ["report_alice"]
    assert preview["to_grant"] == ["report_alice"]
    assert preview["kept_by_other_chain"] == ["report_bob"]
    assert preview["losing_unchecked"] == []
    assert preview["fingerprint"] == before["fingerprint"]
    assert "CASCADE" in preview["revoke_statement"]

    # 预演不改变库内权限
    assert _state(client) == before


def test_preview_t2_unchecked_losing_is_reported(web):
    client, _grants = web
    preview = _preview(client, "T2", [])
    assert preview["losing"] == ["report_carol"]
    assert preview["to_grant"] == []
    assert preview["losing_unchecked"] == ["report_carol"]


def test_confirm_t1_revokes_chain_and_regrants_only_checked_losing(web):
    client, _grants = web
    preview = _preview(client, "T1", ["report_alice", "report_bob"])
    res = _confirm(client, "T1", preview["checked"], preview["fingerprint"])
    assert res.status_code == 200, res.text
    result = res.json()["result"]
    assert result["revoked"] == "duty_alpha"
    assert result["granted"] == ["report_alice"]
    assert result["skipped"] == ["report_bob"]
    assert result["fingerprint_before"] == preview["fingerprint"]
    assert result["fingerprint_after"] != preview["fingerprint"]

    state = _state(client)
    temps = _temps(state)
    assert temps["T1"]["exists"] is False
    assert temps["T2"]["exists"] is True

    accounts = _accounts(state)
    # 勾选且将失权限的账号获得属主的普通 SELECT（独立授权）
    assert accounts["report_alice"]["can_read"] is True
    assert accounts["report_alice"]["direct"] is True
    assert accounts["report_alice"]["chains"] == []
    # 走两条链的账号独立授权保留，未获补授
    assert accounts["report_bob"]["can_read"] is True
    assert accounts["report_bob"]["chains"] == ["T2"]
    assert accounts["report_bob"]["direct"] is False
    assert accounts["report_carol"]["can_read"] is True

    edges = {
        (e["grantor"], e["grantee"])
        for e in state["edges"]
        if e["privilege_type"] == "SELECT"
    }
    # 依赖 T1 的转授（duty_alpha、duty_gamma 发出的）全部消失
    assert not any(grantor in ("duty_alpha", "duty_gamma") for grantor, _ in edges)
    assert (state["owner"], "report_alice") in edges
    # T2 链原样保留
    assert (state["owner"], "duty_beta") in edges
    assert ("duty_beta", "report_bob") in edges
    assert ("duty_beta", "report_carol") in edges

    # 交接后按库内权限真实查表
    assert _try_query(client, "report_alice")["ok"] is True
    assert _try_query(client, "report_bob")["ok"] is True
    assert _try_query(client, "report_carol")["ok"] is True


def test_confirm_t2_keeps_t1_chain_untouched(web):
    client, _grants = web
    preview = _preview(client, "T2", ["report_carol"])
    res = _confirm(client, "T2", preview["checked"], preview["fingerprint"])
    assert res.status_code == 200, res.text
    assert res.json()["result"]["granted"] == ["report_carol"]

    accounts = _accounts(_state(client))
    assert accounts["report_alice"]["chains"] == ["T1"]
    assert accounts["report_alice"]["can_read"] is True
    assert accounts["report_bob"]["chains"] == ["T1"]
    assert accounts["report_carol"]["direct"] is True
    assert accounts["report_carol"]["can_read"] is True


def test_unchecked_account_loses_access_and_try_query_shows_it(web):
    client, _grants = web
    preview = _preview(client, "T1", [])
    res = _confirm(client, "T1", [], preview["fingerprint"])
    assert res.status_code == 200, res.text
    assert res.json()["result"]["granted"] == []

    denied = _try_query(client, "report_alice")
    assert denied["ok"] is False
    assert "权限不足" in denied["error"]

    allowed = _try_query(client, "report_bob")
    assert allowed["ok"] is True
    assert len(allowed["rows"]) >= 6
    assert {"id", "service", "version", "environment", "status", "deployed_at"} <= set(
        allowed["rows"][0]
    )


def test_confirm_with_stale_fingerprint_is_rejected_and_changes_nothing(web):
    client, _grants = web
    first = _preview(client, "T1", ["report_alice"])
    res = _confirm(client, "T1", first["checked"], first["fingerprint"])
    assert res.status_code == 200, res.text
    state_after_first = _state(client)

    # 同一指纹再次确认：授权链已变化，必须拒绝且不改动任何权限
    stale = _confirm(client, "T1", first["checked"], first["fingerprint"])
    assert stale.status_code == 409
    body = stale.json()
    assert body["ok"] is False
    assert body["kind"] == "HandoverConflict"
    assert "重新预演" in body["error"]
    assert _state(client) == state_after_first

    # 预演之后授权链被他处改动（此处用重置模拟），旧指纹同样失效
    second = _preview(client, "T2", ["report_carol"])
    reset = client.post("/api/handover/reset")
    assert reset.status_code == 200
    rejected = _confirm(client, "T2", second["checked"], second["fingerprint"])
    assert rejected.status_code == 409
    assert rejected.json()["kind"] == "HandoverConflict"


def test_concurrent_confirms_are_serialized_and_only_one_wins(web):
    client, grants = web
    preview = _preview(client, "T1", ["report_alice"])
    outcomes: list[str] = []

    def worker():
        try:
            grants.confirm("T1", ["report_alice"], preview["fingerprint"])
            outcomes.append("ok")
        except grants.HandoverConflict:
            outcomes.append("conflict")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["conflict", "ok"]
    accounts = _accounts(_state(client))
    assert accounts["report_alice"]["direct"] is True
    assert _temps(_state(client))["T1"]["exists"] is False


def test_failed_confirm_rolls_back_and_keeps_original_permissions(web, monkeypatch):
    client, grants = web
    preview = _preview(client, "T1", ["report_alice"])
    before = _state(client)

    def boom(conn, account):
        raise RuntimeError("simulated grant failure")

    monkeypatch.setattr(grants, "_grant_select", boom)
    with pytest.raises(RuntimeError):
        grants.confirm("T1", ["report_alice"], preview["fingerprint"])

    # 撤权与补授都未生效：授权链与预演时完全一致
    assert _state(client) == before


def test_service_restart_keeps_database_permissions(web, database_url, monkeypatch):
    client, _grants = web
    preview = _preview(client, "T1", ["report_alice"])
    assert _confirm(client, "T1", preview["checked"], preview["fingerprint"]).status_code == 200
    before = _state(client)

    # 模拟服务重启：重新加载应用模块并重新进入生命周期
    monkeypatch.setenv("DATABASE_URL", database_url)
    for name in list(sys.modules):
        if name.startswith("app."):
            del sys.modules[name]
    import app.config
    import app.db
    import app.drill
    import app.grants
    import app.main

    importlib.reload(app.config)
    importlib.reload(app.db)
    app.drill = importlib.reload(app.drill)
    app.grants = importlib.reload(app.grants)
    app.main = importlib.reload(app.main)

    with TestClient(app.main.app):
        after = app.grants.read_state()
        assert after == before  # 重启未重置任何库内权限
        assert _temps(after)["T1"]["exists"] is False
        assert app.grants.try_query("report_alice")["ok"] is True
        denied = app.grants.try_query("report_carol")
        assert denied["ok"] is True  # T2 链在重启后依然有效
    app.drill.store.shutdown()


def test_try_query_restricted_to_sample_accounts(web):
    client, _grants = web
    res = client.post("/api/handover/query", data={"account": "duty_alpha"})
    assert res.status_code == 400
    assert res.json()["ok"] is False


def test_unknown_grant_and_unknown_account_rejected(web):
    client, _grants = web
    res = client.post("/api/handover/preview", data={"grant_id": "T9"})
    assert res.status_code == 400
    assert res.json()["ok"] is False

    res = client.post(
        "/api/handover/preview", data={"grant_id": "T1", "checked": ["report_mallory"]}
    )
    assert res.status_code == 400
    assert res.json()["ok"] is False


def test_html_flow_preview_then_confirm(web):
    client, _grants = web
    page = client.get("/handover")
    assert page.status_code == 200
    assert "临时授权" in page.text
    assert "report_alice" in page.text

    res = client.post(
        "/handover/preview", data={"grant_id": "T1", "checked": ["report_alice"]}
    )
    assert res.status_code == 200
    assert "预演结果" in res.text
    assert "未修改任何权限" in res.text
    fingerprint = re.search(r'name="fingerprint" value="([0-9a-f]+)"', res.text).group(1)

    res = client.post(
        "/handover/confirm",
        data={"grant_id": "T1", "fingerprint": fingerprint, "checked": ["report_alice"]},
    )
    assert res.status_code == 200
    assert "交接完成" in res.text
    assert _accounts(_state(client))["report_alice"]["direct"] is True

    # 行锁演练页导航到交接页
    index = client.get("/")
    assert index.status_code == 200
    assert "/handover" in index.text
