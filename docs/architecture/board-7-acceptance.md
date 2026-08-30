# Board 7 验收记录

验收对象：执行策略冻结与凭据提供者边界，版本 `0.7.0`。

## 交付结论

通过。策略输入不包含交易正文；每条主路径和备用路径均在 Workflow
启动前获得摘要绑定的决定。拒绝返回安全的 403，策略提供者异常返回安全的
503，审批要求被固化为耐久审批边界。

凭据目录仅保存租户、环境、适配器、能力和不透明引用。真实值只在 worker
Activity 内解析为短期 lease；作用域或摘要不匹配、提供者缺失、部分解析失败
均 fail closed，并在成功和所有失败路径关闭已创建 lease。

## 复用判断

- 保留 Temporal 作为耐久执行器，不在 Workflow 中调用外部策略或密钥服务；
- 使用已有 Pydantic、SQLite、HTTPX2 边界，未引入新的策略 DSL 或密钥库；
- OPA 接口采用严格 HTTPS 兼容形状，但不宣称部署了真实 OPA；
- 环境变量和内存 provider 仅用于显式本地/引导场景，生产 secret manager
  由部署方注入同一协议。

## 安全验收

- 决策、规则、策略集、输入及凭据绑定均带可重算 SHA-256 摘要；
- API 主体以 issuer/subject 的稳定哈希进入策略输入，不携带 bearer token；
- policy provider 无交易 payload、adapter output 或 secret；
- Workflow 历史只保存 credential binding digest，不保存引用解析结果；
- credential-aware adapter 不可绕过 Activity credential boundary；
- secret lease 在成功、适配器异常和部分解析异常时均关闭；
- 错误、repr、诊断不回显 secret bytes。

## 验证结果

```text
Board 7 policy tests                 18 passed
Board 7 credential contract tests   13 passed
Runtime policy integration           9 passed
Runtime credential integration       9 passed
Full test suite                     317 passed, 1 skipped
ruff check .                        passed
mypy src                            passed (77 source files)
git diff --check                    passed
```

跳过项是既有的、需要本机浏览器条件的测试，不影响离线核心验收。

## 明确未声称完成

- 未接入真实 Vault/KMS、企业 OPA 或云端身份平台；
- 未配置任何船司真实账号、密钥或生产凭据；
- 未宣称实现 HSM、进程内存硬隔离或操作系统级安全擦除；
- 未新增对外凭据管理 API，避免在缺少管理面授权设计时扩大攻击面。
