---
name: dotnet-code-audit
description: >-
  Sophon .NET / C# 代码审计总控。用于授权范围内完成项目侦察、路由与鉴权映射、数据流追踪、危险 Sink 审计、反序列化、文件、Web 输出、配置、依赖、WebForms 和证据化报告。
metadata:
  tags: [代码审计, dotnet, csharp, aspnet, 安全审计]
---

# Sophon .NET 代码审计总控

本技能是 .NET / C# 项目审计入口。专项规则位于对应的 `dotnet-*` 技能，共享分级和证据标准位于 `../dotnet-shared/`。

## 适用范围

- ASP.NET Core、ASP.NET MVC、Web API、Minimal API。
- Razor Pages、MVC Views、Blazor Server/WebAssembly。
- ASP.NET WebForms、Web Services、WCF 和传统 IIS 应用。
- .NET Framework、.NET Core、.NET 5 及以上版本。
- 后台服务、Console、Class Library 和定时任务。
- C#、VB.NET、Razor、CSHTML、XAML、配置文件、项目文件和程序集。

## 输入

| 变量 | 必填 | 说明 |
|---|---|---|
| `source_path` | 是 | 项目根目录、`.sln`、`.csproj` 或程序集目录 |
| `output_path` | 否 | 工作区内输出目录，默认 `{source_path}_audit` |
| `audit_mode` | 否 | `standard`、`quick`、`targeted` 或 `binary` |
| `audit_scope` | 否 | 项目、模块、路由、控制器或漏洞类型 |
| `framework_hint` | 否 | ASP.NET Core、MVC、WebForms、Blazor 等 |
| `authorized_only` | 是 | 必须确认授权 |
| `decompile_allowed` | 否 | 默认 `no` |

缺少源码/程序集路径或授权范围时，只返回最小补充输入。

## 二进制审计性能边界

- 禁止直接对 `bin/*.dll`、`*.dll` 或整个依赖目录执行全量反编译和调用链扫描。
- 先从源码、配置和路由定位业务程序集，再用 `rg -a -l` 或字符串搜索缩小到命中 DLL。
- 排除明确的框架、运行时和第三方依赖；无法确认时先记录，不要批量深度解析。
- 单批最多 50 个程序集，每批必须有超时和结果上限；达到目标命中数或时间预算后停止。
- 自定义解析器必须缓存 PE、Metadata 表和字符串堆，禁止在每个 token 循环中重复读取整张表。
- 全量扫描只能作为用户明确授权后的独立任务，并需要分批、可恢复进度和资源上限。
- 用户明确允许反编译且本地存在 `ilspycmd` 时，优先调用 `dotnet_decompile`；每次只处理一个确认过的业务程序集，输出必须写入会话工作区。dnSpy GUI 不作为 Agent 的 headless 执行入口。

## 审计流程

### 阶段 1：项目与入口侦察

读取：

- `.sln`、`.csproj`、`.props`、`.targets`、`global.json`。
- `Program.cs`、`Startup.cs`、`web.config`、`app.config`。
- `appsettings*.json`、`launchSettings.json`、`NuGet.Config`。
- Controllers、Areas、Pages、Minimal API、WebForms、WCF 和后台任务。

识别：

- 目标框架、运行时、项目类型、包引用和部署形态。
- 路由、中间件顺序、认证方案、授权策略、CORS、CSRF。
- 数据访问框架、序列化库、模板和文件/HTTP 操作。

### 阶段 2：路由与鉴权

加载 `dotnet-route-auth-audit`：

- 建立入口、HTTP 方法、参数和鉴权矩阵。
- 检查 `[Authorize]`、`[AllowAnonymous]`、Policy、Role、Claim 和自定义中间件。
- 检查 IDOR、模型绑定、Mass Assignment、CSRF 和 CORS。

### 阶段 3：危险 Sink 初筛

按类别扫描：

- SQL/NoSQL、命令、表达式、模板、SSRF。
- 反序列化和 XML。
- 文件读取、写入、上传、下载、解压。
- Razor/Blazor 输出、重定向和响应头。
- 配置、密钥、Cookie、JWT 和 DataProtection。
- NuGet 依赖。

每个命中只标记为 `PATTERN`，直到数据流和入口证据闭合。

危险 Sink 审计不能把“当前方法没有字符串拼接特征”当作安全结论。必须检查完整危险文本是否由形参、请求字段或上游 helper 透传，以及最终 Sink 是否实际创建并传入参数。典型遗漏形态是“SQL 文本整体透传 + 下游零 `SqlParameter` 执行”。

### 阶段 4：数据流追踪

加载 `dotnet-dataflow-trace`，从以下 Source 开始：

- MVC/Web API 参数和 `[FromBody]`、`[FromQuery]`、`[FromForm]`、`[FromRoute]`。
- `HttpRequest`、`Request.Query`、`Request.Form`、`Request.Headers`、`Request.Cookies`。
- `IFormFile`、JSON body、SignalR 消息、gRPC 请求、后台队列消息。
- WebForms 控件、QueryString、Cookies、Session、ViewState。

追踪到对应 Sink，记录文件、行号、方法、分支和防护。

### 阶段 5：专项审计

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

没有对应 Sink 时不启动专项技能。`NOT_APPLICABLE` 必须写否定证据和扫描范围。

### 阶段 6：报告

推荐输出：

```text
{output_path}/recon/
{output_path}/routes/
{output_path}/findings.json
{output_path}/quality_report.md
{output_path}/PARTIAL_RESULTS.md  # 仅中断或未完成时
```

报告必须包含覆盖矩阵、漏洞详情、证据链、候选利用链、未闭合项、依赖风险和修复建议。

## 证据状态

- `CONFIRMED`：入口、参数、分支和 Sink 闭合。
- `NEEDS_VALIDATION`：存在强线索但条件缺失。
- `ENV_DEPENDENT`：依赖 IIS、Windows 身份、MachineKey、权限、TLS 或部署配置。
- `PATTERN`：仅命中危险模式。
- `NOT_EXPLOITABLE`：有有效防护或 Sink 不可达。

## 安全边界

1. 仅分析授权范围内的本地文件。
2. 不执行 `dotnet run/test/build/restore`、MSBuild target、PowerShell 或项目代码。
3. 不自动安装 SDK、NuGet、ILSpy、dnSpy 或扫描器。
4. 不访问真实服务、NuGet API、Advisory 数据库或云资源。
5. 反编译只使用已存在工具，并需明确许可。
6. 不修改源码、项目文件、锁文件或配置。
7. 静态 PoC 只写入报告，不在审计过程中发送。
8. 中间产物和报告只写当前会话工作区。

共享规范：

- `../dotnet-shared/SEVERITY_RATING.md`
- `../dotnet-shared/EVIDENCE_STANDARD.md`
- `../dotnet-shared/SINK_REFERENCE.md`
- `../dotnet-shared/SOPHON_RUNTIME.md`
