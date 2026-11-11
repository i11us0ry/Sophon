# .NET 审计证据标准

## 每条发现必填

- Finding ID。
- 类型代码。
- 严重度和 CVSS。
- 状态和证据置信度。
- 项目、模块和目标框架。
- 路由、方法或服务入口。
- Source 文件和行号。
- 中间变量、验证和分支。
- Sink 文件、行号和 API。
- 类名和方法签名。
- 参数可控性。
- 鉴权和部署前置条件。
- 修复建议。
- 未验证项。

## 证据格式

```text
Source:
  file:line
  symbol:
  request/input:

Flow:
  file:line -> file:line
  transformations:
  validation:
  branches:

Sink:
  file:line
  symbol:
  dangerous_argument:
```

## 置信度

| 等级 | 条件 |
|---|---|
| HIGH | 入口、Source、参数流、分支、Sink 和防护检查均有 file:line 证据 |
| MEDIUM | 数据流基本成立，但缺少一个关键配置、框架默认行为或部署条件 |
| LOW | 只有危险 API、字符串或模式命中 |

`LOW` 不得标记为 `CONFIRMED`。

## 代码摘录

- 只摘录证明结论所需的最小代码片段。
- 每段代码必须保留相对路径和行号。
- 不引用未实际读取的文件。
- 不根据类名或方法名猜测漏洞。
- 配置证据必须注明 ASPNETCORE_ENVIRONMENT、web.config 继承或部署层可能覆盖。

## 覆盖矩阵

每个审计面必须标记：

- `EXECUTED`：已执行并有产物锚点。
- `NOT_APPLICABLE`：有明确否定证据。
- `DEFERRED`：有残留风险和补做条件。

证据不足的项不得从报告中删除，必须进入待补证池。
