# 大板块二验收记录

验收对象：耐久交易运行时，版本 `0.2.0`。

## 已实现子板块

### 2.1 执行计划与状态机

实现不可变 `cargomesh.execution-plan/v1`、显式能力绑定、步骤依赖、超时、
重试、审批和补偿契约。状态机拒绝未声明跃迁，终态不包含含糊的 `SUCCESS`；
执行完成只能是 `EXECUTED_UNVERIFIED`。

### 2.2 幂等提交账本

SQLite 参考实现使用 `(tenant_id, idempotency_key)` 唯一约束和
`BEGIN IMMEDIATE`。相同摘要并发请求收敛到同一 transaction/workflow id；
不同摘要返回冲突；Temporal 启动失败后复用原 id 重试。

该账本只记录提交索引，不复制 Temporal 历史，也不充当业务证据库。

### 2.3 Temporal 耐久编排

复用官方 `temporalio` 1.32 SDK，实现 Workflow、Pydantic data converter、
Activity、审批/取消信号、状态查询、SDK retry policy 和反序补偿。Workflow
只做确定性决策；网络、文件、适配器和外部系统访问只存在于 Activity。

### 2.4 适配器边界

实现 Worker 侧注册表、统一 invocation/result envelope 和安全错误分类。
未知适配器、未知操作、异常结果全部失败关闭。仓库只有明确标注的合成只读
适配器，用于离线测试和本地演示，不代表任何真实船司。

### 2.5 交易 API

实现创建、状态查询、审批和取消端点。创建必须携带 `Idempotency-Key`；首次
提交返回 202，等价重放返回 200。未装配运行时返回稳定 503，错误不会泄露
Temporal、SQLite、路径或 traceback。

## Sol 集成复核

- 修正审批拒绝/取消与补偿状态之间的合法跃迁；
- 并发启动使用确定性 workflow id，Temporal 重复启动视为同一执行；
- 业务载荷拒绝 password/token/secret 等疑似凭证字段，只允许凭证引用；
- 写操作发生未补偿效果时不得标记 `COMPENSATED`；
- Activity 失败视为副作用结果未知，失败写步骤本身也必须执行幂等补偿；
- 默认 API 不暗中启动本地执行器；本地演示必须显式开启 synthetic binding；
- 使用真实 Temporal 时移测试服务完成 Worker、审批信号、Activity 和结果序列化冒烟。

## 验收门

```text
pytest                         全部通过（75 项）
ruff check .                   全部通过
mypy src --strict              全部通过
cargomesh-dcsa check           所有固定来源摘要一致
uv build                       sdist + wheel 成功
真实 Temporal SDK smoke        EXECUTED_UNVERIFIED
wheel 独立安装 smoke           通过
```

浏览器/船司适配器、执行路径优化、OPA/OpenFGA、独立证据裁决和生产级分布式
SQL 控制面不属于大板块二，不以空壳形式提前加入。
