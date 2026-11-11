---
name: dotnet-dataflow-trace
description: >-
  .NET / C# Source-to-Sink 数据流追踪。用于追踪 MVC、Minimal API、Razor、Blazor、WebForms、gRPC、SignalR 和后台任务输入到 SQL、命令、文件、HTTP、反序列化、XML 和 Web 输出 Sink 的完整路径。
metadata:
  tags: [dotnet, 数据流, taint, 代码审计]
---

# .NET 数据流追踪

本技能只输出数据流和可控性证据，不直接给漏洞等级或修复建议。

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

## 输出格式

```text
Entry:
  route_id:
  file:line
  symbol:

Source:
  file:line
  expression:

Flow:
  1. file:line symbol transformation
  2. file:line branch/validation
  3. file:line symbol

Sink:
  file:line
  api:
  argument:

Controllability: FULL | CONDITIONAL | NONE | UNKNOWN
Branch Evidence:
Protection:
Trace Status: COMPLETE | PARTIAL | UNRESOLVED
```

## 规则

1. 每个关键跳转必须有 file:line。
2. 不能只凭方法名判断参数可控。
3. 无法追踪反射、动态代理或运行时注册时标记 `PARTIAL/UNRESOLVED`。
4. `UNKNOWN` 不得升级为已确认漏洞。
5. 未闭合路径必须进入待补证池。
6. 不使用真实请求验证。
