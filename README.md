# PostgreSQL 演练台

包含两个演练页：

- **行锁演练（`/`）**：当一个 `UPDATE` 被 PostgreSQL 行锁挂住时，从网页上找出**真实**的持锁者，
  并只解除本演练造成的这一次阻塞。
- **权限交接（`/handover`）**：临时值班组退出后，接班人仍要查部署报表。撤回选定的临时
  SELECT 授权（连带依赖它的转授），只给仍需读报表且会失去权限的账号补授。

## 权限交接演练

样例表 `public.deploy_report`（部署报表）与真实角色在首次启动时自动准备，预置两笔
**可分别撤回**的临时 `SELECT` 授权：

```
T1（含两级转授）：属主 → duty_alpha ──(WITH GRANT OPTION 转授)──> duty_gamma ──(转授)──> report_alice、report_bob
T2（一级转授）  ：属主 → duty_beta  ──(WITH GRANT OPTION 转授)──> report_bob、report_carol
```

因此 `report_alice` 只走 T1 一条授权链，`report_carol` 只走 T2 一条，`report_bob`
同时走 T1、T2 两条。

交接流程：

1. **选择**：值班员在页面上选定要撤回的一笔临时授权，勾选交接后仍需读报表的账号。
2. **预演**：页面列出「仅撤权就会失去查询权限的账号」与「本次要补授的账号」
   （勾选且将失权限者）。预演只读取系统目录，**不修改库内权限**。
3. **确认**：撤权与补授在**同一事务**生效——
   - 确认时在事务内复核该表的授权链指纹，指纹与预演不一致（授权链已被改动）即
     **拒绝交接并提示重新预演**；并发确认由 PostgreSQL 咨询锁串行化，后到者必然
     看到指纹变化而被拒；
   - `REVOKE … CASCADE` 撤掉所选授权和依赖它的转授，仅给勾选且将失去读权限的账号
     补普通 `SELECT`，其余独立授权原样保留；
   - 任一语句失败即整体回滚，保留原权限。
4. **验证**：页面上可按样例报表账号实际查表（`SET ROLE` 后真实 `SELECT`），显示
   结果或权限不足。权限全部落在数据库里，**服务重启后仍按库内权限查询**。

页面另提供「恢复初始授权链」按钮，用于反复演练。应用角色需要能创建样例角色
（compose 中的 `drill` 为超级用户；自建角色需 `CREATEROLE`）。

## 行锁演练

## 功能

- **真实数据库会话**：每轮演练在 PostgreSQL 中创建两个连接
  - 持锁会话：`BEGIN` 后执行 `SELECT ... FOR UPDATE` 锁住演练行（`idle in transaction`）；
  - 受阻更新：另一连接执行 `UPDATE lock_drill_row …`，被行锁挂住。
- **页面展示**：两端 PID、`backend_start`（会话启动时间）、事务开始时间、当前状态、
  `wait_event_type/wait_event`、`pg_blocking_pids()` 给出的**实际阻塞者**、
  双方持有的锁及阻塞关系明细表。
- **安全解除**
  - 只在「当前演练状态为 blocked，且数据库刚确认 `holder_pid ∈ pg_blocking_pids(waiter_pid)`」
    时开放按钮；
  - 提交时用**单条 SQL**（`_TERMINATE_IF_STILL_BLOCKING_SQL`）原子地复核
    「原会话仍存活（pid + backend_start + 记录中的 application_name）且仍阻塞原更新」，
    复核通过才 `pg_terminate_backend`，因此 pid 复用、会话改名、阻塞关系变化都不会误杀。
  - 页面令牌与轮次一一对应：旧页面（会话结束、服务重启、开始新一轮后）提交会被
    403/410 拒绝，绝不会关闭新会话。
- **以真实结果判定**：解锁后等待受阻连接真实执行 `COMMIT`；判定只看
  `UPDATE ... RETURNING` + `COMMIT` 的结果，并用独立连接复核行值。
  - 终止失败、命令返回成功但 `COMMIT` 未完成、或仍存在其他阻塞者时，判定为
    **未恢复**，并列出当前阻塞者。
  - 重复提交返回同一判定，不会再次终止任何会话。
- **清理**：`结束本轮演练`、开始新一轮、服务关闭都会按身份三元组终止本演练的两个会话；
  启动时清理上一进程遗留的 `lockdrill:drill:*` 会话。

## 运行（Docker Compose）

```bash
docker compose up --build
# 打开 http://localhost:8000
```

`docker compose` 会启动 PostgreSQL 16 与 Web 应用。Web 服务固定单 worker，
因为演练会话与页面令牌保存在进程内（会话本身在 PostgreSQL 中）。

## 本地运行

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://drill:drill@localhost:5432/drill
uvicorn app.main:app --port 8000
```

## 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql://drill:drill@localhost:5432/drill` | 应用连接串 |
| `DRILL_SESSION_PREFIX` | `lockdrill` | 会话 `application_name` 前缀 |
| `BLOCK_CONFIRM_SECONDS` | `5` | 等待数据库确认阻塞关系的时间 |
| `RELEASE_WAIT_SECONDS` | `10` | 终止后等待受阻更新真实结束的时间 |
| `REFUSED_WAIT_SECONDS` | `2` | 未终止时等待其自行结束的时间 |
| `DRILL_TTL_SECONDS` | `1800` | 超时自动结束的演练时长 |
| `DB_CONNECT_TIMEOUT` | `5` | 连接超时（秒） |

> 注意：生产库上使用 `pg_terminate_backend` 需要相应权限；演练请使用专用数据库/角色。

## 测试

测试需要真实 PostgreSQL（会创建 `lock_drill_test` / `lock_handover_test` 角色与数据库，
请指向一次性实例）：

```bash
TEST_DATABASE_URL=postgresql://postgres@localhost/postgres pytest -q
```

行锁演练覆盖：真实阻塞关系、正常解锁恢复、服务重启后的旧页面、结束演练后的旧页面、
会话身份被篡改（拒绝终止且不释放锁）、终止成功但无提交结果（判未恢复）、
旧会话已消失但更新已提交（按真实结果判恢复）、重复解锁幂等。

权限交接覆盖：初始授权链形态（两级转授、单链/双链账号）、预演只读且列出失权与补授账号、
撤 T1/T2 后链与独立授权的去留、未勾选账号真实失去查询权限、指纹过期拒绝且不改权限、
并发确认只有一笔生效、补授失败整体回滚、服务重启后仍按库内权限查询、试查接口的账号白名单。

## 接口

- 行锁演练：`GET /`、`POST /drill/start`、`GET /drill/{id}`、
  `POST /drill/{id}/release`、`POST /drill/{id}/end`（表单，含 `token`）；
  `GET /api/state`、`GET /api/drills/{id}`、`POST /api/drills/{id}/release|end`（JSON）
- 权限交接：`GET /handover`、`POST /handover/preview|confirm|query|reset`（表单）；
  `GET /api/handover/state`、`POST /api/handover/preview|confirm|query|reset`（JSON）
- `GET /healthz`
