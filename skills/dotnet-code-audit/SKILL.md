---
name: dotnet-code-audit
description: >-
  Sophon .NET / C# 代码审计总控。用于完成项目侦察、路由与鉴权映射、数据流追踪、危险 Sink 审计、反序列化、文件、Web 输出、配置、依赖、WebForms 和证据化报告
metadata:
  tags: [代码审计, dotnet, csharp, aspnet, 安全审计]
---

# Sophon .NET 代码审计总控

本技能是 .NET / C# 项目审计入口。专项规则位于对应的 `dotnet-*` 技能，共享分级和证据标准位于 `../dotnet-shared/`。

## 适用场景

适合从 ASP.NET 项目源码、项目文件或业务程序集开始，建立入口、鉴权、数据流、危险 Sink 和证据化结论。

## 不适用场景

如果只检查一个已知方法、一个配置项或一个依赖，可直接使用对应 Skill，不必启动完整审计路径。

## 核心判断

审计路径由项目结构、可达入口和证据缺口决定。阶段、路由数量、Sink 命中数和依赖命中数都不能替代真实数据流与安全影响。

## 证据标准

- 漏洞结论必须绑定文件、行号、方法、数据流、分支和 Sink。
- 路由、配置和依赖命中先视为候选。
- 二进制审计必须区分元数据字符串、反编译结果和运行时行为。
- 证据不闭合时标记 PARTIAL、UNRESOLVED 或 ENV_DEPENDENT。

## 决策树

- 项目和入口未知：先识别项目结构、框架和部署形态。
- 路由或鉴权未知：加载 `dotnet-route-auth-audit`。
- Sink 命中：加载 `dotnet-dataflow-trace` 和对应专项 Skill。
- 参数不可控或分支不可达：降低结论等级。
- 证据闭合且安全影响明确：进入漏洞写回和报告。

## 常见误判

- 把 Sink 关键字命中当成漏洞。
- 把缺少 `[Authorize]` 当成确定未授权。
- 把依赖版本命中当成可利用。
- 把反编译中的字符串当成运行时执行证据。
- 为完成六阶段而制造低价值结论。

## 适用范围

- ASP.NET Core、ASP.NET MVC、Web API、Minimal API。
- Razor Pages、MVC Views、Blazor Server/WebAssembly。
- ASP.NET WebForms、Web Services、WCF 和传统 IIS 应用。
- .NET Framework、.NET Core、.NET 5 及以上版本。
- 后台服务、Console、Class Library 和定时任务。
- C#、VB.NET、Razor、CSHTML、XAML、配置文件、项目文件和程序集。

## 分析视角

### 项目与入口侦察

读取：

- `.sln`、`.csproj`、`.props`、`.targets`、`global.json`。
- `Program.cs`、`Startup.cs`、`web.config`、`app.config`。
- `appsettings*.json`、`launchSettings.json`、`NuGet.Config`。
- Controllers、Areas、Pages、Minimal API、WebForms、WCF 和后台任务。

识别：

- 目标框架、运行时、项目类型、包引用和部署形态。
- 路由、中间件顺序、认证方案、授权策略、CORS、CSRF。
- 数据访问框架、序列化库、模板和文件/HTTP 操作。

### 路由与鉴权

可参考 `dotnet-route-auth-audit`：

- 建立入口、HTTP 方法、参数和鉴权矩阵。
- 检查 `[Authorize]`、`[AllowAnonymous]`、Policy、Role、Claim 和自定义中间件。
- 检查 IDOR、模型绑定、Mass Assignment、CSRF 和 CORS。

### 危险 Sink 初筛

按类别扫描：

- SQL/NoSQL、命令、表达式、模板、SSRF。
- 反序列化和 XML。
- 文件读取、写入、上传、下载、解压。
- Razor/Blazor 输出、重定向和响应头。
- 配置、密钥、Cookie、JWT 和 DataProtection。
- NuGet 依赖。

每个命中只标记为 `PATTERN`，直到数据流和入口证据闭合。

危险 Sink 审计不能把“当前方法没有字符串拼接特征”当作安全结论。可继续检查完整危险文本是否由形参、请求字段或上游 helper 透传。

### 数据流追踪

可参考 `dotnet-dataflow-trace`，从以下 Source 开始：

- MVC/Web API 参数和 `[FromBody]`、`[FromQuery]`、`[FromForm]`、`[FromRoute]`。
- `HttpRequest`、`Request.Query`、`Request.Form`、`Request.Headers`、`Request.Cookies`。
- `IFormFile`、JSON body、SignalR 消息、gRPC 请求、后台队列消息。
- WebForms 控件、QueryString、Cookies、Session、ViewState。

追踪到对应 Sink，记录文件、行号、方法、分支和防护。

### 专项审计

| 审计面 | 技能 |
|---|---|
| 路由、鉴权、IDOR、CSRF、CORS | `dotnet-route-auth-audit` |
| SQL、NoSQL、命令、表达式、模板、SSRF | `dotnet-injection-audit` |
| 反序列化、ViewState、XML/XXE | `dotnet-deserialization-xml-audit` |
| 文件、上传、写入、路径、解压 | `dotnet-file-audit` |
| Razor、Blazor、XSS、重定向、CRLF | `dotnet-web-output-audit` |
| 配置、密钥、JWT、Cookie、TLS、DataProtection | `dotnet-config-crypto-audit` |
| NuGet 依赖 | `dotnet-dependency-audit` |
| WebForms 和传统 IIS | `dotnet-legacy-webforms-audit` |
| 证据复核和最终报告 | `dotnet-reporting` |

没有对应 Sink 时可只记录否定证据和扫描范围。

### 报告

路由、鉴权和候选风险写回项目审计台账；证据闭合的漏洞使用 `project_report_finding`，不强制固定输出目录。

报告可包含覆盖范围、漏洞详情、证据链、候选利用链、未闭合项、依赖风险和修复建议。

## 证据状态

- `CONFIRMED`：入口、参数、分支和 Sink 闭合。
- `NEEDS_VALIDATION`：存在强线索但条件缺失。
- `ENV_DEPENDENT`：依赖 IIS、Windows 身份、MachineKey、权限、TLS 或部署配置。
- `PATTERN`：仅命中危险模式。
- `NOT_EXPLOITABLE`：有有效防护或 Sink 不可达。
