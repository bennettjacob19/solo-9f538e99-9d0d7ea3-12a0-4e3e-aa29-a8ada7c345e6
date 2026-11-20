"""权限交接演练：部署报表上的临时 SELECT 授权与交接。

场景：临时值班组退出后，接班人仍要查部署报表。库内以真实角色预置两笔
可分别撤回的临时 SELECT 授权：

* T1（含两级转授）：
    属主 → duty_alpha（WITH GRANT OPTION）
    duty_alpha → duty_gamma（WITH GRANT OPTION）   —— 第一级转授
    duty_gamma → report_alice、report_bob           —— 第二级转授
* T2（一级转授）：
    属主 → duty_beta（WITH GRANT OPTION）
    duty_beta → report_bob、report_carol

因此 report_alice 只走 T1 一条授权链，report_carol 只走 T2 一条，
report_bob 同时走 T1、T2 两条。

交接 = 撤回值班员选定的那笔临时授权（REVOKE … CASCADE，连带依赖它的
转授），并只给「勾选且仅撤权后会失去读权限」的报表账号补普通 SELECT；
其余独立授权原样保留。撤权与补授在同一事务生效，失败整体回滚，保留
原权限。

预演只读取系统目录，不修改任何库内权限。确认时在同一事务内复核授权链
指纹：指纹不同（授权链已被改动）即拒绝交接并提示重新预演；并发确认由
PostgreSQL 咨询锁串行化，后到者必然观察到指纹变化而被拒。

所有权限都落在数据库里（pg_class.relacl），服务重启后仍按库内权限查询。
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
from typing import Any

import psycopg
from psycopg import sql

from .config import settings
from .db import connect

logger = logging.getLogger("lockdrill.handover")

SCHEMA = "public"
TABLE = "deploy_report"
TABLE_NAME = f"{SCHEMA}.{TABLE}"
_TABLE_REF = sql.SQL("{}.{}").format(sql.Identifier(SCHEMA), sql.Identifier(TABLE))

DUTY_ALPHA = "duty_alpha"
DUTY_GAMMA = "duty_gamma"
DUTY_BETA = "duty_beta"
REPORT_ACCOUNTS: tuple[str, ...] = ("report_alice", "report_bob", "report_carol")
SAMPLE_ROLES: tuple[str, ...] = (DUTY_ALPHA, DUTY_GAMMA, DUTY_BETA, *REPORT_ACCOUNTS)

TEMPORARY_GRANTS: dict[str, dict[str, str]] = {
    "T1": {
        "grantee": DUTY_ALPHA,
        "title": "临时授权 T1（值班组 Alpha，含两级转授）",
        "chain_text": "属主 → duty_alpha →(转授)→ duty_gamma →(转授)→ report_alice、report_bob",
    },
    "T2": {
        "grantee": DUTY_BETA,
        "title": "临时授权 T2（值班组 Beta，一级转授）",
        "chain_text": "属主 → duty_beta →(转授)→ report_bob、report_carol",
    },
}

SEED_ROWS: list[tuple[str, str, str, str]] = [
    ("api-gateway", "2.14.0", "prod", "success"),
    ("order-service", "5.3.1", "prod", "success"),
    ("order-service", "5.4.0-rc.1", "staging", "running"),
    ("billing-worker", "1.9.2", "prod", "failed"),
    ("report-center", "3.0.4", "prod", "success"),
    ("auth-service", "4.2.0", "canary", "running"),
]

_QUERY_COLUMNS = ["id", "service", "version", "environment", "status", "deployed_at"]


class HandoverError(Exception):
    """权限交接操作失败。"""

    status_code = 400


class HandoverConflict(HandoverError):
    """授权链在预演之后发生了变化，或交接锁被他人持有。"""

    status_code = 409


def _iso(value: Any) -> Any:
    if isinstance(value, dt.datetime):
        return value.isoformat(sep=" ", timespec="microseconds")
    return value


# ---------------------------------------------------------------------------
# 授权链读取与推算（全部基于数据库系统目录的实时内容）
# ---------------------------------------------------------------------------

_OWNER_SQL = """
SELECT pg_get_userbyid(c.relowner) AS owner
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %(schema)s AND c.relname = %(table)s
"""

_EDGES_SQL = """
SELECT pg_get_userbyid(a.grantor) AS grantor,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type,
       a.is_grantable
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(c.relacl) AS a
WHERE n.nspname = %(schema)s AND c.relname = %(table)s
ORDER BY grantor, grantee, a.privilege_type, a.is_grantable
"""


def _read_graph(conn: psycopg.Connection[Any]) -> tuple[str, list[dict[str, Any]]]:
    """返回 (表属主, 授权边列表)。每条边 = 一条 (grantor → grantee) 权限记录。"""
    params = {"schema": SCHEMA, "table": TABLE}
    row = conn.execute(_OWNER_SQL, params).fetchone()
    if row is None:
        raise HandoverError(f"样例表 {TABLE_NAME} 不存在，请先完成初始化。")
    edges = conn.execute(_EDGES_SQL, params).fetchall()
    return row["owner"], [dict(edge) for edge in edges]


def _select_closure(
    edges: list[dict[str, Any]], owner: str
) -> tuple[set[str], set[str]]:
    """沿 WITH GRANT OPTION 链推算 (能 SELECT 的角色, 持有 SELECT 转授权的角色)。"""
    has_select = {owner}
    has_option = {owner}
    changed = True
    while changed:
        changed = False
        for edge in edges:
            if edge["privilege_type"] != "SELECT":
                continue
            if edge["grantor"] not in has_option:
                continue
            grantee = edge["grantee"]
            if grantee not in has_select:
                has_select.add(grantee)
                changed = True
            if edge["is_grantable"] and grantee not in has_option:
                has_option.add(grantee)
                changed = True
    return has_select, has_option


def _can_read(has_select: set[str], account: str) -> bool:
    return account in has_select or "PUBLIC" in has_select


def _fingerprint(owner: str, edges: list[dict[str, Any]]) -> str:
    """授权链指纹：覆盖该表每一条授权记录与属主，任何变动都会改变它。"""
    lines = [f"owner={owner}"]
    lines.extend(
        sorted(
            f"{e['grantor']}->{e['grantee']}:{e['privilege_type']}:"
            f"{'grantable' if e['is_grantable'] else 'plain'}"
            for e in edges
        )
    )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _temporary_grant_exists(
    edges: list[dict[str, Any]], owner: str, grantee: str
) -> bool:
    return any(
        e["grantor"] == owner and e["grantee"] == grantee and e["privilege_type"] == "SELECT"
        for e in edges
    )


def _edges_without_temporary(
    edges: list[dict[str, Any]], owner: str, grantee: str
) -> list[dict[str, Any]]:
    """模拟撤回一笔临时授权（属主 → grantee 的 SELECT）后的授权边。"""
    return [
        e
        for e in edges
        if not (
            e["grantor"] == owner
            and e["grantee"] == grantee
            and e["privilege_type"] == "SELECT"
        )
    ]


def _edges_only_through(
    edges: list[dict[str, Any]], owner: str, first_grantee: str
) -> list[dict[str, Any]]:
    """只保留「从属主出发、首条边为 属主→first_grantee」的路径可经过的边。"""
    return [e for e in edges if e["grantor"] != owner or e["grantee"] == first_grantee]


def _losing_accounts(
    edges: list[dict[str, Any]], owner: str, grantee: str
) -> list[str]:
    """仅撤回该笔临时授权就会失去查询权限的报表账号。"""
    before, _ = _select_closure(edges, owner)
    after, _ = _select_closure(_edges_without_temporary(edges, owner, grantee), owner)
    return [
        account
        for account in REPORT_ACCOUNTS
        if _can_read(before, account) and not _can_read(after, account)
    ]


def _require_grant(grant_id: str) -> dict[str, str]:
    grant = TEMPORARY_GRANTS.get(grant_id)
    if grant is None:
        raise HandoverError(f"未知的临时授权 {grant_id!r}。")
    return grant


def _validate_accounts(checked: list[str]) -> list[str]:
    unknown = [a for a in checked if a not in REPORT_ACCOUNTS]
    if unknown:
        raise HandoverError(f"未知报表账号：{'、'.join(unknown)}")
    wanted = set(checked)
    return [a for a in REPORT_ACCOUNTS if a in wanted]


def _lock_key() -> str:
    return f"{settings.session_prefix}:handover:{TABLE_NAME}"


# ---------------------------------------------------------------------------
# 页面状态
# ---------------------------------------------------------------------------


def read_state() -> dict[str, Any]:
    """实时读取库内授权链，供页面与 API 展示（不写任何东西）。"""
    with connect(
        application_name=f"{settings.session_prefix}:handover:state", autocommit=True
    ) as conn:
        owner, edges = _read_graph(conn)
        row_count = conn.execute(
            sql.SQL("SELECT count(*) AS c FROM {}").format(_TABLE_REF)
        ).fetchone()["c"]

    has_select, _ = _select_closure(edges, owner)
    accounts: list[dict[str, Any]] = []
    for account in REPORT_ACCOUNTS:
        chains = []
        for grant_id, grant in TEMPORARY_GRANTS.items():
            sub_select, _ = _select_closure(
                _edges_only_through(edges, owner, grant["grantee"]), owner
            )
            if _can_read(sub_select, account):
                chains.append(grant_id)
        direct = any(
            e["grantor"] == owner
            and e["grantee"] == account
            and e["privilege_type"] == "SELECT"
            for e in edges
        )
        accounts.append(
            {
                "name": account,
                "can_read": _can_read(has_select, account),
                "chains": chains,
                "direct": direct,
            }
        )

    temporary = []
    for grant_id, grant in TEMPORARY_GRANTS.items():
        temporary.append(
            {
                "id": grant_id,
                "title": grant["title"],
                "grantee": grant["grantee"],
                "chain_text": grant["chain_text"],
                "exists": _temporary_grant_exists(edges, owner, grant["grantee"]),
                "covers": [a["name"] for a in accounts if grant_id in a["chains"]],
            }
        )

    return {
        "table": TABLE_NAME,
        "owner": owner,
        "row_count": row_count,
        "fingerprint": _fingerprint(owner, edges),
        "edges": edges,
        "temporary_grants": temporary,
        "accounts": accounts,
    }


# ---------------------------------------------------------------------------
# 预演（只读，不修改库内权限）
# ---------------------------------------------------------------------------


def preview(grant_id: str, checked: list[str]) -> dict[str, Any]:
    grant = _require_grant(grant_id)
    checked = _validate_accounts(checked)
    with connect(
        application_name=f"{settings.session_prefix}:handover:preview", autocommit=True
    ) as conn:
        owner, edges = _read_graph(conn)
    if not _temporary_grant_exists(edges, owner, grant["grantee"]):
        raise HandoverConflict(
            f"临时授权 {grant_id}（属主 → {grant['grantee']}）已不存在，"
            "授权链与页面显示不一致，请刷新后重新预演。"
        )
    losing = _losing_accounts(edges, owner, grant["grantee"])
    to_grant = [a for a in checked if a in losing]
    return {
        "grant_id": grant_id,
        "grantee": grant["grantee"],
        "title": grant["title"],
        "checked": checked,
        "losing": losing,
        "to_grant": to_grant,
        "kept_by_other_chain": [a for a in checked if a not in losing],
        "losing_unchecked": [a for a in losing if a not in checked],
        "revoke_statement": f"REVOKE SELECT ON {TABLE_NAME} FROM {grant['grantee']} CASCADE",
        "grant_statements": [f"GRANT SELECT ON {TABLE_NAME} TO {a}" for a in to_grant],
        "fingerprint": _fingerprint(owner, edges),
    }


# ---------------------------------------------------------------------------
# 确认交接（单事务：复核指纹 → 撤权 CASCADE → 补授；失败整体回滚）
# ---------------------------------------------------------------------------


def _revoke_temporary(conn: psycopg.Connection[Any], grantee: str) -> None:
    conn.execute(
        sql.SQL("REVOKE SELECT ON {} FROM {} CASCADE").format(
            _TABLE_REF, sql.Identifier(grantee)
        )
    )


def _grant_select(conn: psycopg.Connection[Any], account: str) -> None:
    conn.execute(
        sql.SQL("GRANT SELECT ON {} TO {}").format(
            _TABLE_REF, sql.Identifier(account)
        )
    )


def confirm(grant_id: str, checked: list[str], expected_fingerprint: str) -> dict[str, Any]:
    grant = _require_grant(grant_id)
    checked = _validate_accounts(checked)
    if not expected_fingerprint:
        raise HandoverError("缺少授权链指纹，请先预演。")

    with connect(
        application_name=f"{settings.session_prefix}:handover:confirm", autocommit=False
    ) as conn:
        conn.execute("SET LOCAL lock_timeout = '15s'")
        try:
            # 串行化并发确认：后到者在前者提交后才能继续，因而必然看到
            # 已变化的授权链并被下面的指纹核对拒绝。
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (_lock_key(),),
            )
        except psycopg.errors.LockNotAvailable as exc:
            raise HandoverConflict(
                "另一场交接正在确认中，未能取得交接锁，请重新预演后再试。"
            ) from exc

        owner, edges = _read_graph(conn)
        fingerprint = _fingerprint(owner, edges)
        if fingerprint != expected_fingerprint:
            raise HandoverConflict(
                "该表的授权链在预演之后已发生变化，本次交接未执行任何修改，请重新预演。"
            )

        # 指纹一致 ⇒ 授权链与预演时完全相同，按当前库内状态重新推算。
        losing = _losing_accounts(edges, owner, grant["grantee"])
        to_grant = [a for a in checked if a in losing]

        _revoke_temporary(conn, grant["grantee"])
        for account in to_grant:
            _grant_select(conn, account)

        owner_after, edges_after = _read_graph(conn)
        fingerprint_after = _fingerprint(owner_after, edges_after)
        # 离开 with 块时提交；任何异常都会回滚，保留原权限。

    return {
        "grant_id": grant_id,
        "revoked": grant["grantee"],
        "losing": losing,
        "granted": to_grant,
        "skipped": [a for a in checked if a not in losing],
        "fingerprint_before": fingerprint,
        "fingerprint_after": fingerprint_after,
    }


# ---------------------------------------------------------------------------
# 以报表账号实际查表（SET ROLE，权限完全由数据库裁决）
# ---------------------------------------------------------------------------

_QUERY_SQL = sql.SQL(
    "SELECT id, service, version, environment, status, deployed_at "
    "FROM {} ORDER BY id LIMIT 20"
).format(_TABLE_REF)


def try_query(account: str) -> dict[str, Any]:
    if account not in REPORT_ACCOUNTS:
        raise HandoverError(f"{account!r} 不是样例报表账号，不允许以其身份查询。")
    try:
        with connect(
            application_name=f"{settings.session_prefix}:handover:tryquery",
            autocommit=True,
        ) as conn:
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(account)))
            rows = conn.execute(_QUERY_SQL).fetchall()
    except psycopg.errors.InsufficientPrivilege as exc:
        detail = exc.diag.message_primary if exc.diag else str(exc)
        return {"account": account, "ok": False, "error": f"权限不足：{detail}"}
    return {
        "account": account,
        "ok": True,
        "columns": _QUERY_COLUMNS,
        "rows": [{key: _iso(row[key]) for key in _QUERY_COLUMNS} for row in rows],
    }


# ---------------------------------------------------------------------------
# 初始化与重置
# ---------------------------------------------------------------------------


def _create_roles_if_missing(conn: psycopg.Connection[Any]) -> list[str]:
    created = []
    for role in SAMPLE_ROLES:
        exists = conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)
        ).fetchone()
        if exists is None:
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
            created.append(role)
    return created


def _ensure_set_role_memberships(conn: psycopg.Connection[Any]) -> None:
    """保证当前连接角色能 SET ROLE 到每个样例角色（试查与转授都依赖它）。

    超级用户不需要任何成员关系；非超级用户的应用角色需要显式成员关系 ——
    PostgreSQL 16 中 CREATEROLE 创建角色时自动获得的成员关系默认
    set_option=false，不能直接 SET ROLE，因此这里补一次显式授权。
    """
    row = conn.execute(
        "SELECT rolsuper FROM pg_roles WHERE rolname = CURRENT_USER"
    ).fetchone()
    if row and row["rolsuper"]:
        return
    missing = conn.execute(
        """
        SELECT r.rolname
        FROM pg_roles r
        WHERE r.rolname = ANY(%(roles)s)
          AND NOT EXISTS (
              SELECT 1
              FROM pg_auth_members m
              JOIN pg_roles member ON member.oid = m.member
              WHERE m.roleid = r.oid
                AND member.rolname = CURRENT_USER
                AND m.set_option
          )
        """,
        {"roles": list(SAMPLE_ROLES)},
    ).fetchall()
    for role in missing:
        try:
            conn.execute(
                sql.SQL("GRANT {} TO CURRENT_USER").format(
                    sql.Identifier(role["rolname"])
                )
            )
        except psycopg.errors.InsufficientPrivilege as exc:
            raise HandoverError(
                f"样例角色 {role['rolname']} 已存在，但当前应用角色对它没有 "
                "ADMIN 权限，无法建立 SET ROLE 所需的成员关系。请改用超级用户/"
                "CREATEROLE 角色，或由管理员预先授权后重启。"
            ) from exc


def _seed_rows(conn: psycopg.Connection[Any]) -> None:
    count = conn.execute(
        sql.SQL("SELECT count(*) AS c FROM {}").format(_TABLE_REF)
    ).fetchone()["c"]
    if count:
        return
    insert = sql.SQL(
        "INSERT INTO {} (service, version, environment, status) VALUES (%s, %s, %s, %s)"
    ).format(_TABLE_REF)
    for row in SEED_ROWS:
        conn.execute(insert, row)


def _create_table_if_missing(conn: psycopg.Connection[Any]) -> bool:
    exists = conn.execute("SELECT to_regclass(%s) AS reg", (TABLE_NAME,)).fetchone()["reg"]
    if exists is not None:
        return False
    conn.execute(
        sql.SQL(
            """
            CREATE TABLE {} (
                id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                service text NOT NULL,
                version text NOT NULL,
                environment text NOT NULL,
                status text NOT NULL,
                deployed_at timestamptz NOT NULL DEFAULT now()
            )
            """
        ).format(_TABLE_REF)
    )
    _seed_rows(conn)
    return True


def _seed_grants(conn: psycopg.Connection[Any]) -> None:
    """施加两笔初始临时授权及其转授链。

    以表属主身份执行；通过 SET ROLE 让每笔转授的 grantor 都是值班角色，
    与值班组亲手转授的效果完全一致。
    """
    # T1：属主 → duty_alpha（可转授），再经 duty_gamma 两级转授到报表账号。
    conn.execute(
        sql.SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(
            _TABLE_REF, sql.Identifier(DUTY_ALPHA)
        )
    )
    conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(DUTY_ALPHA)))
    conn.execute(
        sql.SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(
            _TABLE_REF, sql.Identifier(DUTY_GAMMA)
        )
    )
    conn.execute(sql.SQL("RESET ROLE"))
    conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(DUTY_GAMMA)))
    for account in ("report_alice", "report_bob"):
        conn.execute(
            sql.SQL("GRANT SELECT ON {} TO {}").format(
                _TABLE_REF, sql.Identifier(account)
            )
        )
    conn.execute(sql.SQL("RESET ROLE"))

    # T2：属主 → duty_beta（可转授），一级转授到报表账号。
    conn.execute(
        sql.SQL("GRANT SELECT ON {} TO {} WITH GRANT OPTION").format(
            _TABLE_REF, sql.Identifier(DUTY_BETA)
        )
    )
    conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(DUTY_BETA)))
    for account in ("report_bob", "report_carol"):
        conn.execute(
            sql.SQL("GRANT SELECT ON {} TO {}").format(
                _TABLE_REF, sql.Identifier(account)
            )
        )
    conn.execute(sql.SQL("RESET ROLE"))


def ensure_handover_schema() -> bool:
    """创建样例角色与样例表；仅在首次建表时施加初始临时授权。

    服务重启时表已存在则不动任何权限 —— 库内权限（包括已完成的交接）
    原样保留，查询始终按库内权限裁决。
    """
    with connect(application_name=f"{settings.session_prefix}:handover:setup") as conn:
        created_roles = _create_roles_if_missing(conn)
        _ensure_set_role_memberships(conn)
        created_table = _create_table_if_missing(conn)
        if created_table:
            _seed_grants(conn)
    if created_table:
        logger.info(
            "handover drill initialised on %s (roles created: %s)",
            TABLE_NAME,
            "、".join(created_roles) or "none",
        )
    return created_table


def reset_handover() -> dict[str, Any]:
    """恢复两笔初始临时授权（显式重置，用于反复演练）。

    先撤掉全部样例角色在该表上的权限（级联清除它们的转授），再重新施加
    初始授权链。与确认交接共用同一把咨询锁，不会与进行中的交接交错。
    """
    with connect(application_name=f"{settings.session_prefix}:handover:reset") as conn:
        conn.execute("SET LOCAL lock_timeout = '15s'")
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (_lock_key(),),
        )
        _create_roles_if_missing(conn)
        _ensure_set_role_memberships(conn)
        _create_table_if_missing(conn)
        _seed_rows(conn)
        for role in SAMPLE_ROLES:
            conn.execute(
                sql.SQL("REVOKE ALL PRIVILEGES ON {} FROM {} CASCADE").format(
                    _TABLE_REF, sql.Identifier(role)
                )
            )
        _seed_grants(conn)
    logger.info("handover drill reset to canonical grants on %s", TABLE_NAME)
    return read_state()
