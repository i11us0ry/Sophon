---
name: dotnet-dataflow-trace
description: >-
  .NET / C# Source-to-Sink 数据流追踪。用于追踪 MVC、Minimal API、Razor、Blazor、WebForms、gRPC、SignalR 和后台任务输入到 SQL、命令、文件、HTTP、反序列化、XML 和 Web 输出 Sink 的完整路径。
metadata:
  tags: [dotnet, 数据流, taint, 代码审计]
---

# .NET 数据流追踪

本技能只输出数据流和可控性证据，不直接给漏洞等级或修复建议。

## 适用场景

适合已经存在明确入口、参数或 Sink 候选，需要证明输入如何跨方法、跨类型和跨分支到达危险操作。

## 不适用场景

如果入口或 Sink 尚未确定，不必对所有代码执行数据流追踪；仅有同名变量或危险 API 名称时，不能补写未观察到的流。

## 核心判断

数据流追踪只回答输入是否以及如何到达 Sink。参数可控性、分支可达、转换、净化和最终执行需要逐段证据。

## 证据标准

- 每个关键跳转必须有 file、line、symbol 和表达式。
- 分支需要记录可达条件与提前退出。
- 参数经过模型绑定、映射、编码、加密或反射时需要记录状态变化。
- Trace 只能标记 COMPLETE、PARTIAL 或 UNRESOLVED，不得把 UNKNOWN 升级为确认。

## 决策树

- Source 和 Sink 明确：按调用链逐层追踪。
- 跨接口或 DI 实现：定位具体实现类。
- 分支存在：分别记录进入和退出路径。
- 防护存在：判断完全阻断、条件阻断或仅编码。
- 动态反射或运行时代理无法解析：标记未闭合并停止该分支。

## 常见误判

- 只凭方法名判断可控性。
- 把 DTO 字段和实体字段自动视为同一值。
- 忽略异步、扩展方法、基类和中间件。
- 把编码当成参数化或白名单。
- 在 PARTIAL 状态下给出 confirmed 结论。

## Source

- MVC 参数：`[FromBody]`、`[FromQuery]`、`[FromForm]`、`[FromRoute]`、`[FromHeader]`。
- `HttpRequest.Query/Form/Headers/Cookies/Body`。
- `IFormFile`、`FormCollection`、`Request.Files`。
- JSON、XML、Form、Multipart 和 protobuf 输入。
- SignalR Hub 参数、gRPC request、Queue、Event Bus。
- WebForms：`Request`、控件值、ViewState、Session、Cookie。
- 配置和数据库输入只有在能证明外部影响时标记为间接 Source。

## 追踪要点

### 参数映射

- 模型绑定、DTO、record、class property。
- AutoMapper、手动映射、隐式转换。
- `JsonSerializer.Deserialize`、Newtonsoft.Json、System.Text.Json。
- `RouteData`、`ViewData`、`TempData`。

### 变量变换

- 字符串插值、`+`、`string.Concat`、`StringBuilder`。
- `Uri`、`Path.Combine`、`Path.GetFullPath`。
- Base64、URL/HTML 编码、加密、解密、压缩。
- LINQ、Select、Where、动态表达式。

### 分支和防护

- `if/switch`、模式匹配、guard clause。
- 白名单、正则、枚举、类型转换、长度限制。
- ModelState、FluentValidation、DataAnnotations。
- Authorization Policy、资源所有权和租户过滤。
- Framework middleware 或 global filter。

### 跨过程

- DI 接口到实现类。
- Extension method、BaseController、Filter、Middleware。
- Async/await、Task、delegate、Expression。
- Repository、Service、UnitOfWork、MediatR。
- Reflection、`Activator.CreateInstance`、动态代理。

## 追踪规则

1. 每个关键跳转必须有 file:line。
2. 不能只凭方法名判断参数可控。
3. 无法追踪反射、动态代理或运行时注册时标记 `PARTIAL/UNRESOLVED`。
4. `UNKNOWN` 不得升级为已确认漏洞。
5. 未闭合路径必须进入待补证池。
6. 不使用真实请求验证。
