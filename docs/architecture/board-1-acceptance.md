# 大板块一验收记录

验收对象：行业协议与 Transaction IR，首个生产能力切片
`shipment.track.read`。

## 团队分工

- Sol：冻结边界与公共契约，负责 IR、映射语义、集成修正、全量验收；
- Tera：实现 DCSA 来源清单、同步/校验、许可证溯源和参考数据底座；
- Luna：实现 FastAPI 接入层、应用服务、依赖注入和安全错误响应；
- Sol 最终验收不采用“子模块测试通过即合并”，而采用完整调用链和安装包测试。

## Sol 复核后的关键修正

1. 将 DCSA 基线固定为稳定 TNT 2.3.0；TNT 3.0 Beta 不进入生产支持矩阵。
2. 补齐 TNT 查询所需 Event、DCSA、Error 三个直接 Domain 文件及逐文件摘要。
3. API 默认接入真实参考数据目录，不接受“空 Provider 也算成功”的假实现。
4. Compile 请求改为显式且 `extra=forbid`，不根据偶然字段猜测协议版本。
5. 将 `eventCreatedDateTime:gte/gt/lte/lt/eq` 规范化成带类型的 IR 谓词，避免运算符丢失。
6. 增加按来源版本、目标版本、业务能力三元组索引的映射注册表。
7. 增加字段级 EXACT/NORMALIZED/DEFAULTED/PARTIAL/UNSUPPORTED diagnostics。
8. 参考数据增加状态、历史有效期和 TNT 2.3 的事件/文档代码；别名只建议，不代替精确匹配。
9. 迁移结果同时给出原始/派生 canonical JSON 和摘要，输入对象不被原地修改。
10. Wheel 强制包含标准快照和 CSV，离开源码目录安装后仍能离线校验。

## 子板块状态

### 4.1 DCSA 标准镜像与同步

已实现固定 commit、许可证、逐文件 URL/SHA-256、离线校验、显式同步、
受支持 SwaggerHub `$ref` 本地化、结构化兼容 diff、Pydantic JSON Schema
输出和查询模型/上游规范守卫。

官方 Conformance Gateway 继续作为外部测试系统复用。本板块没有 DCSA
事件执行端点，因此当前不伪造 Conformance 通过；等适配器与运行时板块提供
可执行 DCSA 角色后启用完整场景门禁。

### 4.2 Transaction IR

已实现严格不可变 v1 模型、主体/过滤器/效果/验证级别/风险/能力/扩展、
UTC 规范化、稳定 canonical JSON 和排除运行时标识的业务摘要。IR 中不存在
selector、坐标或浏览器概念。

### 4.3 DCSA ↔ CargoMesh 映射

已实现 TNT 2.3 查询双向映射、映射注册表、字段级精度诊断、代码表校验、
日期运算符无损映射和往返测试。未知扩展或超出固定标准的代码在反向映射时
产生 blocking diagnostic，不会静默丢失。

### 4.4 IR 迁移与兼容

已实现显式有向迁移图及 v0alpha1 → v1 纯迁移。未知路径失败关闭，派生结果
保留迁移步、迁移前后文档和摘要。Temporal replay 属于运行时板块，不在此处
引入伪 Workflow。

### 4.5 对外 API

已实现健康检查、能力发现、两类 JSON Schema、编译和参考数据读取。错误包含
稳定 code/request_id 且不暴露 traceback。创建/取消交易、幂等持久化和 202
长事务接口必须依赖后续交易运行时，因此当前只暴露真实可完成的“编译”语义。

### 4.6 参考数据与代码表

已实现 version/status/validity/alias 数据模型、历史查询、精确匹配和单独的
模糊建议通道。默认目录提供 44 个来自固定 TNT/Event Domain 的代码值。

## 验收门

交付前必须同时满足：

```text
pytest                         全部通过
ruff check .                   全部通过
mypy src --strict              全部通过
cargomesh-dcsa check           所有固定来源摘要一致
uv build                       sdist + wheel 成功
安装 wheel 后离线 source check 成功
安装 wheel 后 API/参考数据导入 smoke test 成功
```

任何单项失败均不得标记大板块一已验收。
