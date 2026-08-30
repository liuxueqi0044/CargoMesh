# 大板块六验收记录

验收对象：多租户身份、授权、API 强制边界与安全审计，版本 `0.6.0`。

## 团队分工

- Sol：冻结总体/安全契约，完成纯领域模型、访问编排、FastAPI/运行时集成、
  跨租户语义、最终复核、完整验收与发布；
- Tera：实现 OIDC/JWKS 认证边界和离线 RSA/JWKS 测试；
- Luna：实现固定 RBAC、SQLite 成员目录、append-only 审计哈希链和存储测试；
- Sol 对交付做安全复核，并补强 HTTPS issuer、标准 JWKS media type、空密钥集、
  provider failure、决策请求绑定、全角色矩阵、篡改字段和真实端到端接线。

## 已实现子板块

### 6.1 外部身份认证边界

CargoMesh 复用外部 OIDC 身份提供商和 PyJWT，不实现密码存储、登录页或 token
签发。`OIDCAuthenticator` 只接受显式 HTTPS issuer、audience、JWKS URL 和算法
allowlist；要求 `iss/sub/aud/iat/exp`，拒绝 `none`/对称算法、错误签名、未知
`kid`、临界 header、失效/未生效/未来签发和超大 token。

`HttpJwksProvider` 只访问一个精确 HTTPS URL，禁用环境代理与重定向，限制 5 秒和
64 KiB，接受标准 `application/jwk-set+json`/`application/json`，缓存 key，并仅在
未知 `kid` 时刷新一次。Bearer token、原始 `jti`、tenant/role claim 不进入后续
模型、日志、数据库或错误正文。

### 6.2 成员目录与固定 RBAC

成员权限只来自服务端 SQLite 目录，并同时绑定 issuer、subject、principal type、
tenant、environment 和 role。七个固定角色覆盖六个稳定 action；42 个角色/action
组合均逐项验收。纯 evaluator 不读取时钟或数据库，并再次核对 provider 返回的完整
scope；无成员、disabled、未知 action 和 provider failure 全部失败关闭。

成员 provision 的精确重放幂等，冲突必须显式 replace；replace 保持身份范围、推进
整数 revision，且禁止角色键碰撞。目录不含 token、claim、密码或业务数据。

### 6.3 API 强制与租户隔离

`create_app()` 的 access controller 仍为可选，从而保持 Board 1–5 离线/本地模式。
开启后，transaction create 使用编译后不可变 IR 的 tenant；read/approve/cancel
先读取资源 tenant 再授权。缺失/错误 bearer 返回 401 与 `WWW-Authenticate`，跨租户
read/approve/cancel 返回同样的 404 且不调用写方法，同租户 action 不足返回 403。

审批人强制替换为验证后的 principal subject。授权 provider 或审计不可用返回 503；
授权审计在业务 mutation 前落盘，outcome 审计在成功响应前落盘，不存在运行时静默
退回未启用模式的路径。

`cargomesh-runtime-api --enforce-access-control` 必须同时配置 issuer、audience、JWKS、
environment、membership DB 和 audit DB；部分、空白或无效 URL 配置在启动阶段失败。

### 6.4 Append-only 审计哈希链

审计事件只保留有界 actor/resource/action/result/reason/request id、decision digest 和
安全标量 details。模型拒绝 secret-like key/value、JWT/Bearer、凭据、绝对文件路径
和过长文本。

SQLite 使用 `BEGIN IMMEDIATE`、tenant 独立 sequence、UPDATE/DELETE trigger 和
canonical digest。event digest 绑定事件；record digest 再绑定前一 record digest。
同 event 精确重放幂等，不同内容冲突；完整验证可定位 sequence、列/JSON、event、
previous digest 或 record digest 的首个损坏位置。

## 复用判断

- 复用客户 IdP/Keycloak、PyJWT、HTTPX2、Pydantic、FastAPI 和 SQLite；
- 不自建密码/token 系统；
- 不引入 OpenFGA/OPA：当前七角色六动作矩阵很小，provider/decision contract 已保留
  日后替换边界；
- 不引入 SQLAlchemy/PostgreSQL：Board 6 是单节点参考实现，分布式控制平面属于后续；
- 不新增审计 payload：业务输入、adapter 输出和 evidence 均不进入安全账本。

## 本地验收门

```text
pytest                              268 passed, 1 skipped
Board 6 定向安全测试                87 passed
ruff check .                        全部通过
mypy src                            全部通过（66 个源码文件）
cargomesh-dcsa check                所有固定来源摘要一致
cargomesh-adapter check             manifest/source_system 校验通过
uv build                            0.6.0 sdist + wheel 成功
wheel 独立安装 smoke                0.6.0 / OIDC / membership / audit imports
真实离线 RSA→membership→API→audit  202 + 双审计记录 + hash chain valid
```

唯一跳过项仍是 Windows 当前账户没有创建符号链接权限；Linux CI 会执行该拒绝路径。
身份提供商托管、成员/审计管理 HTTP API、PostgreSQL/多节点目录和 audit export 不属于
大板块六。
