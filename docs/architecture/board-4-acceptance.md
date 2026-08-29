# 大板块四验收记录

验收对象：跨渠道证据验证与可审计裁决，版本 `0.4.0`。

## 团队分工

- Sol：冻结证据与独立性架构，完成纯验证引擎、运行时/Temporal/浏览器来源
  集成、安全复核、真实端到端验收和最终发布；
- Tera：实现独立合成 system-of-record 服务，并补齐模型、引擎和 collector
  registry 的边界测试；
- Luna：实现 HTTP 证据 collector、append-only SQLite 收据库及其测试；
- Sol 对两个子模块逐项复核，并亲自修正跨模块契约与高风险边界。

## 已实现子板块

### 4.1 证据与报告契约

`EvidenceObservation`、`VerificationPlan` 和 `VerificationReport` 均为严格、
不可变、拒绝未知字段的 Pydantic 合约。证据包含 tenant/transaction、来源记录、
source system、channel、collector/collection、时效、有限标量 claims、synthetic
标记和规范化 SHA-256。

报告绑定 transaction id 与 Board 1 的 canonical business digest，包含 required/
achieved level、逐 claim 结果、收据摘要、受限 reason code 和自身摘要。摘要篡改、
naive datetime、过期顺序、NaN/Infinity、secret-like 字段和超限 JSON 都会被拒绝。

### 4.2 确定性验证与 L0–L3

纯函数引擎不调用网络、数据库、LLM 或时间源；时间作为显式参数输入。独立级别由
provenance 计算：独立 collector/session 为 L1，脱离所有执行 source system 为
L2，至少两个非执行 source system 且跨两个 channel 才为 L3。

全量 claim 匹配且达到要求才是 `VERIFIED`；充分独立的矛盾/不匹配证据进入
`NEEDS_REVIEW`；缺失、陈旧、过期、未来、身份错误、expected value 缺失或独立性
不足进入 `HALTED`。执行结果本身永远不能充当自己的证据。

### 4.3 独立采集与 append-only 收据

证据 collector 使用与 execution adapter 完全分离的 registry。HTTP collector
固定执行只读 `GET`，只接受配置的 origin，禁用重定向与环境代理，校验响应状态、
content type、schema、source/channel/reference，并在流式解码超过 64 KiB 时立即
中止。错误只穿越安全 code，不携带 URL 或响应 body。

SQLite 收据以 `(tenant_id, evidence_id)` 为主键，文件库启用 WAL，写入使用
`BEGIN IMMEDIATE`，trigger 禁止 UPDATE/DELETE。同 id/same digest 重放幂等，
different digest 硬冲突；读取时重新验证模型和摘要。

### 4.4 Durable Workflow 集成

执行步骤输出携带 typed `ExecutionSource`。Adapter manifest 升级为 v2，要求
`source_system`，并声明最低 CargoMesh `0.4.0`，避免静默改变 v1 合约。

Workflow 在无验证计划或 L0 时保留 `EXECUTED_UNVERIFIED`。有计划时进入
`VERIFYING`，执行独立 verification Activity；报告映射为 `VERIFIED`、
`NEEDS_REVIEW` 或 `HALTED`。Activity 或收据错误安全停止；报告若不匹配当前
transaction、business digest 或 required level，也以
`verification_report_mismatch` 停止。

### 4.5 独立合成验收链路

Board 3 合成门户和 Board 4 合成 ledger 是两个不同 FastAPI 进程与 source system。
ledger 支持 healthy、conflict、missing、stale、server-error 和有界延迟，始终显式
标记 synthetic。

真实端到端测试启动两个本地 HTTP 服务和真实 headless Chromium：浏览器从
`synthetic.portal` 执行 recipe，独立 HTTP collector 再从 `synthetic.ledger`
采集同一 shipment，收据先落库，最终达到 L2 并生成 synthetic `VERIFIED` 报告。

## Sol 集成复核后的关键修正

1. 修正 datetime/Enum/default 值在签发与复核之间的 canonical digest 表示；
2. 将报告绑定 canonical business digest，并在模型与 Workflow 两层检查 verdict
   语义和报告身份；
3. 让规划器、collector 和合成服务统一使用 `carrier_booking_reference` 与 `fetch`；
4. 证据/collection id 改为稳定有界哈希，避免长标识超限和跨交易收据冲突；
5. 将 HTTP body 改成边读边限流，补齐 redirect、content type、subject、operation、
   response size 和 origin 边界；
6. 将 SQLite/冲突错误转换为安全 Temporal ApplicationError，并确保收据在裁决前
   写入；
7. 规定独立性/身份/时效不足优先 `HALTED`，不允许低可信矛盾伪装成已验证的
   review 结论；
8. Adapter manifest 使用 v2 承载必需 provenance，而不是破坏原 v1 schema。

## 本地验收门

```text
pytest                              148 passed, 1 skipped
Board 4 真实跨进程 Chromium 链路   VERIFIED / achieved L2
ruff check .                        全部通过
mypy src                            全部通过（53 个源码文件）
cargomesh-dcsa check                所有固定来源摘要一致
cargomesh-adapter check             manifest v2 / source_system 校验通过
uv build                            sdist + wheel 成功
wheel 独立安装 smoke                0.4.0 / VerificationReport / evidence CLI
```

唯一跳过项仍是 Windows 当前账户没有创建符号链接权限；Linux CI 会实际执行该
拒绝路径。真实船司凭证/适配器、邮件/PDF 证据、L3 生产级多来源接线、路由优化、
AI repair、生产鉴权和分布式数据库不属于大板块四。
