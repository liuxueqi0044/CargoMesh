# 大板块三验收记录

验收对象：确定性浏览器适配器与 Adapter CI，版本 `0.3.0`。

## 团队分工

- Sol：冻结整体架构、浏览器安全边界、Worker 集成，并做真实 Chromium 与
  安装包验收；
- Tera：实现适配器包加载、摘要校验、内置 recipe 和检查 CLI；
- Luna：实现可控故障的本地合成物流门户；
- Sol 逐项复核子模块，不以局部单测替代完整调用链验收。

## 已实现子板块

### 3.1 版本化适配器包

实现 `cargomesh.adapter-manifest/v1` 与
`cargomesh.browser-recipe/v1`。加载器离线读取严格 UTF-8 JSON，限制单文件
1 MiB，拒绝缺失、额外 recipe、路径逃逸、符号链接、重复键、未知字段、摘要篡改、
operation/capability 错配和高于当前运行时的最低版本要求。

内置 `synthetic.browser.track` recipe 的固定摘要为：

```text
sha256:fcd232716661dfe92ab21d4b89771b3de3852ab4de6ec6d30b1b9b4ff97255ce
```

### 3.2 受限只读 recipe

只允许相对路径导航、语义定位器填充/点击、可见等待、文本断言和有界文本提取。
schema 中不存在 CSS/XPath、屏幕坐标、任意 JavaScript、固定 sleep、上传、
下载、绝对 URL 或凭证字段。recipe 必须以导航开始、声明门户签名、保持输出名
唯一且最多 100 个动作。

### 3.3 隔离浏览器执行器

复用官方 Playwright Python `1.62.0`，共享浏览器进程但每次调用创建新的
非持久化 `BrowserContext`。固定 locale、timezone、viewport、color scheme
和 reduced motion，阻止 service worker，关闭下载接收。

HTTP 路由只允许配置的精确 origin 和 `GET`/`HEAD`/`OPTIONS`。跨域请求、
HTTP 写、popup 或 download 均使整个 invocation 非重试失败；不会因页面操作
完成而忽略策略违规。

### 3.4 门户签名与故障分类

首次导航后、任何填充或点击前检查 heading、label 和 synthetic notice 三个
签名探针。缺失、歧义或文本不符返回非重试
`portal_drift_detected`，不猜测备用 selector。HTTP 5xx 单独返回可重试
`portal_server_error`，不会误报为页面漂移。

### 3.5 安全诊断与 trace

失败 trace 默认关闭；只有显式注入 artifact sink 才采集。跨 Activity 边界只
传递随机 artifact id、类型、内容类型、长度和 SHA-256，不传文件路径或字节。
内存与文件 sink 均有大小上限。

### 3.6 合成门户与运行时接线

合成门户包含 `CBR-001 / IN_TRANSIT` 与 `CBR-002 / DELIVERED`，并支持
`label_drift`、`silent_drop`、`server_error` 和有界延迟。Board 2 Planner、
Worker registry 和 runtime API 增加显式 browser binding；未开启 flag 时不会
暗中启用浏览器或假装连接真实船司。

执行完成仍只能进入 `EXECUTED_UNVERIFIED`。门户返回文本和 Playwright trace
都不是独立业务证据。

## Sol 集成复核后的关键修正

1. 把 CargoMesh 包/API 版本统一到 `0.3.0`，并真正执行 manifest 最低版本门禁；
2. 在签名中加入表单 label，使 `label_drift` 在 fill/click 之前停止；
3. 在同源限制之外增加安全 HTTP method 门禁，防止只读 recipe 被页面表单诱导
   发出 POST；
4. 将 HTTP 503 与 DOM 漂移分开分类，保留正确重试语义；
5. 对跨域子资源、HTTP 写、上下文回收和 opaque trace 使用真实 Chromium 验证；
6. 让安全的 adapter error type 穿过 Temporal Activity 边界成为查询可见的
   `failure_code`，同时拒绝任意异常文本；
7. 修正全库两个 `test_cli.py` 的 pytest 导入冲突，避免局部测试通过而 CI 收集失败；
8. 增加独立 `Adapter CI`，在 Linux 安装真实 Chromium 后执行全库、静态检查、
   构建和 wheel 安装 smoke。

## 本地验收门

```text
pytest                              110 passed, 1 skipped
真实 Chromium Adapter CI           5 passed
ruff check .                        全部通过
mypy src                            全部通过（45 个源码文件）
cargomesh-dcsa check                所有固定来源摘要一致
cargomesh-adapter check             固定 manifest/recipe 校验通过
uv build                            sdist + wheel 成功
wheel 独立安装 smoke                0.3.0 / synthetic.browser.track
```

唯一跳过项是 Windows 当前账户没有创建符号链接权限；对应拒绝路径已实现且测试
保留，GitHub Linux Adapter CI 会实际执行。

真实船司账号与 recipe、AI 自动修复、跨渠道证据裁决、生产凭证服务、OS/容器级
网络沙箱和分布式控制面不属于大板块三，不以不安全占位实现提前加入。
