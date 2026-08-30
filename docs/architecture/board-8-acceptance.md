# Board 8 验收记录

验收对象：客户网络内 Private Runner 参考边界，版本 `0.8.0`。

## 交付结论

通过。仓库现在具有可离线运行的 runner 注册表、SQLite 任务传输、租约 fencing、
heartbeat/recovery、结果收据和 artifact metadata relay。沙箱、浏览器 session、
版本兼容、canary/drain/rollback 与三类部署 profile 形成不可变验证契约。

这是一套控制边界和单节点参考传输，不等同于已部署客户网络 daemon、生产 mTLS、
CA、容器/VM 隔离或对象存储。

## 架构验收

- enrollment token 随机、短期、一次性，数据库只保存 SHA-256；
- runner 私钥不在任何输入模型中，身份只固定 public-key digest；
- runner scope 固定 tenant/environment/pool/capability，撤销或离线后不能取任务；
- lease acquisition 原子化，重新获取必须增加 fencing token；
- 过期 lease 不会被 acquire 静默重放，必须先执行 recovery；
- effect 前且有 checkpoint 才能重新排队；effect 后或未知状态转入 reconciliation；
- result receipt 对同一 fenced 结果幂等，不同结果冲突；
- artifact 依据类型、MIME、大小、classification、sanitization 检查；
- blob 经注入 sink 处理，SQLite 只保存摘要和不透明引用；
- consequential sandbox 禁止 process-only 隔离，并要求明确 egress；
- AI repair 只允许独立非生产 VM zone；developer profile 明确不可生产使用。

## 复用判断

- 继续使用 SQLite 作为离线单节点元数据参考，不自造消息中间件；
- 远程租约、对象存储、CA/mTLS、容器 runtime 均定义为可替换边界；
- SemVer 范围比较使用小型确定性实现，没有为三段版本比较引入依赖；
- 不把本地 in-memory artifact sink 包装成生产对象存储。

## 验证结果

```text
Runner identity/registry tests        6 passed
Runner task transport tests          11 passed
Artifact/security/release tests       13 passed
Cross-module runner tests              2 passed
Board 8 targeted total                32 passed
Full test suite                      349 passed, 1 skipped
ruff check .                         passed
mypy src                             passed (85 source files)
git diff --check                     passed
```

## 外部验收阻塞项

- 客户 CA、证书轮换、mTLS 终止和反向连接；
- Linux/Windows/macOS 安装器及系统服务管理；
- 真实容器/VM 沙箱、企业代理与 egress firewall；
- 外部对象存储、断点续传与本地加密缓冲；
- 客户网络内的 Temporal/控制面连通性和灾难恢复演练。
