# 大板块五验收记录

验收对象：执行路径优化器、结果健康度与安全降级，版本 `0.5.0`。

## 团队分工

- Sol：冻结总体架构与模块契约，完成路由模型/纯引擎、运行时/Temporal/CLI
  集成、安全复核、真实双路径验收和最终发布；
- Tera：实现独立合成 tracking API 与严格 HTTP execution adapter；
- Luna：实现 append-only SQLite route outcome 账本、健康聚合与熔断测试；
- Sol 对两个交付逐项复核，打回并修正摘要、健康空值、冷却时间、Workflow
  fallback 和跨进程接线等高耦合边界。

## 已实现子板块

### 5.1 候选路径与策略合约

`RouteCandidate` 描述 capability、adapter、operation、API/EDI/BROWSER/HUMAN
channel、先验成功率、延迟、成本、风险/数据敏感度/验证上限、审批、超时/重试和
明确允许降级的安全错误码。`RoutingPolicy` 描述 allow/deny、可靠性/延迟/成本门限、
风险/敏感度/验证门限、权重、历史窗口和 circuit 阈值/冷却期。

两者均为严格不可变 Pydantic 合约，并用 canonical SHA-256 绑定完整内容。决策同时
绑定 request、policy id/version/digest、健康快照、全部候选摘要、拒绝原因、分项
得分、完整排序、选择和 fallback 顺序；Temporal 只消费冻结结果，不读取策略、
数据库、时钟或健康状态。

### 5.2 确定性过滤与整数评分

纯路由引擎先做 capability、enable、channel、allow/deny、risk、data
classification、verification、approval、cost、latency、reliability 和 circuit
硬门禁，再对合格路径计算整数 basis-point 分数。历史成功率通过显式 prior weight
和真实样本合成；不存在浮点金额、随机数、LLM 或不可重放时间读取。

排序固定为 score 降序、static priority 升序、candidate id 升序。没有合格路径时
产生受限 `no_eligible_route`，在 Workflow 启动前失败。

### 5.3 Outcome 账本、健康度与熔断

每个 routed Adapter Activity attempt 写入一条 digest-bound `RouteOutcome`，仅包含
tenant/transaction/step/candidate/Temporal attempt、SUCCESS/RETRYABLE_FAILURE/
TERMINAL_FAILURE、安全错误码、延迟和时间；不落 transaction input、adapter output
或异常正文。

SQLite 以 `(tenant_id,event_id)` 隔离，文件模式启用 WAL，写入用 `BEGIN
IMMEDIATE`，triggers 禁止 UPDATE/DELETE。同事件同摘要重放幂等，不同摘要冲突，
读取时重新校验模型和摘要。健康聚合使用有界最近窗口、整数 nearest-rank p95、
成功率、连续失败和最新事件；样本不足为 `UNKNOWN`，连续失败达到阈值且仍在冷却期
才为 `UNAVAILABLE`，冷却过期自动回到可评估的 `DEGRADED`。

### 5.4 Durable 安全降级

ExecutionPlan 与 ExecutionSnapshot 保存完整 RouteDecision；Snapshot 另外保存每次
RouteAttempt 的候选、adapter、SUCCEEDED/FAILED 和安全错误码。失败历史不会被后续
成功覆盖。

Workflow 只在三个条件同时成立时进入下一个冻结候选：步骤是 `READ_ONLY`、当前
候选明确列出收到的 ApplicationError code、下一个候选已在决策中。未知错误和未
声明错误停止；可逆写和后果性写在模型层禁止自动 fallback，继续沿用补偿/人工复核
语义。Outcome 账本失败被隔离，不能把已经成功的业务 Activity 反转成重试。

### 5.5 合成 API/浏览器双路径

独立 FastAPI 服务提供固定 `CBR-001`/`CBR-002` tracking 数据以及 healthy、
server_error、malformed、not_found 和有界延迟。HTTP adapter 固定只读 GET，禁用
环境代理与重定向，限制解压后响应为 64 KiB，严格验证 content type、schema、
source、subject、字段集合和 reference，并输出与浏览器一致的 `output.data` 形状。

默认策略在空/健康历史选择 `synthetic.api.track`，并冻结
`synthetic.browser.track` 为安全 fallback。真实验收同时启动 API、门户和独立
ledger 三个本地 HTTP 服务：API 路径先达到 L2 `VERIFIED`；注入三次近期 API
失败后，新规划在 Workflow 前排除 open circuit，以真实 headless Chromium 执行
浏览器路径，并再次达到 L2 `VERIFIED`。

## 复用判断

- 复用 Pydantic、SQLite、Temporal Activity、HTTPX2、FastAPI、Playwright 和
  Board 4 verifier；
- 不引入 OR-Tools：当前最多 16 个互相独立候选，确定性过滤/排序比通用求解器更小、
  更易审计；
- 不内嵌 OPA：保留 policy id/version/digest 和 provider 边界，后续可接 OPA REST/
  Wasm，而不让部署复杂度先于真实多租户需求；
- 不新增 OpenTelemetry SDK：append-only outcome 是路由事实源，未来 exporter 可从
  同一受限事件投递 telemetry。

## 本地验收门

```text
pytest                              181 passed, 1 skipped
Board 5 真实三服务/Chromium 双路径  API VERIFIED L2 / browser VERIFIED L2
ruff check .                        全部通过
mypy src                            全部通过（59 个源码文件）
cargomesh-dcsa check                所有固定来源摘要一致
cargomesh-adapter check             manifest v2 / source_system 校验通过
uv build                            sdist + wheel 成功
wheel 独立安装 smoke                0.5.0 / routing API / synthetic API CLI
```

唯一跳过项是 Windows 当前账户没有创建符号链接权限；Linux CI 会实际执行该拒绝路径。
真实船司 API/EDI/人工执行器、生产级策略服务、分布式 outcome 存储、跨节点 circuit、
生产鉴权和自动网页修复不属于大板块五。
