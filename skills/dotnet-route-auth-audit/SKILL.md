---
name: dotnet-route-auth-audit
description: >-
  .NET / C# Web 路由与鉴权审计。用于提取 ASP.NET Core、MVC、Web API、Minimal API、Razor Pages 和 WebForms 入口，检查认证、授权、Policy、Role、Claim、IDOR、CSRF、CORS 和模型绑定风险。
metadata:
  tags: [dotnet, 路由, 鉴权, aspnet]
---

# .NET 路由与鉴权审计

## 适用场景

适合项目存在 ASP.NET Core、MVC、Web API、Minimal API、Razor Pages、Blazor、WebForms 或 WCF 入口，需要建立路由与鉴权矩阵。

## 不适用场景

如果项目没有 Web 入口，或只需要分析后台任务和配置，不应强行生成路由矩阵。

## 核心判断

路由是否存在鉴权不能只看单个特性。需要结合全局 Filter、Policy、中间件、约定、控制器和方法级覆盖判断最终有效权限。

## 证据标准

- 路由需要绑定方法、路径、参数来源和处理器。
- 鉴权结论需要说明全局策略、局部覆盖和中间件顺序。
- IDOR 需要资源所有权或租户过滤证据。
- CSRF、CORS 和 Mass Assignment 需要结合请求方式和凭据形态。

## 决策树

- 路由明确：检查控制器、方法和全局授权策略。
- `[AllowAnonymous]` 存在：核对是否只影响预期公开动作。
- 资源 ID 进入查询：检查 Owner/Tenant 条件。
- Cookie 认证配合状态变更：检查 CSRF 证据。
- CORS 与凭据同时存在：检查来源、凭据和实际读取影响。

## 常见误判

- 没有 `[Authorize]` 就断言未授权。
- 忽略全局 Policy 或 FallbackPolicy。
- 把登录认证当成资源授权。
- 把 SameSite 当成完整 CSRF 防护。
- 把宽松 CORS 配置直接当成数据泄露。

## 目标

建立完整入口与鉴权矩阵，识别匿名入口、授权缺口、越权、模型绑定和跨站请求风险。本技能不推测服务端权限，必须从代码和配置找证据。

## 路由发现

### ASP.NET Core MVC / Web API

- `[Route]`、`[HttpGet]`、`[HttpPost]`、`[ApiController]`。
- `MapControllers`、`MapControllerRoute`、Area 路由。
- Conventional routes、Attribute routes、RoutePrefix。

### Minimal API

- `MapGet`、`MapPost`、`MapPut`、`MapDelete`、`MapMethods`、`MapGroup`。
- Route group、Endpoint filter、自定义 endpoint convention。

### Razor Pages / Blazor

- `@page`、PageModel、`OnGet/OnPost`。
- Blazor `@page`、Hub、SignalR method。

### WebForms / WCF

- `.aspx`、`.ashx`、`.asmx`、`.svc`。
- `Page_Load`、`WebMethod`、WCF operation contract。

## 鉴权检查

识别：

- `AddAuthentication`、JWT Bearer、Cookie、Negotiate、OpenIdConnect。
- `[Authorize]`、`[AllowAnonymous]`、`AddAuthorization`、Policy、Role、Claim。
- `UseAuthentication`、`UseAuthorization`、自定义 Middleware、Filter、Endpoint filter。
- ASP.NET Identity、自定义用户、租户和资源所有权判断。

重点检查：

1. 控制器/方法是否缺少授权。
2. `[AllowAnonymous]` 是否覆盖敏感动作。
3. 全局 Policy 是否被局部覆盖。
4. 中间件顺序是否正确。
5. 资源 ID 是否校验当前用户所有权。
6. 租户 ID 是否来自可信上下文而非请求参数。
7. API Controller 和 Razor Page 是否使用一致的权限模型。

## IDOR 与 Mass Assignment

检查：

- `FindAsync(id)`、`FirstOrDefault(x => x.Id == id)` 后是否校验 Owner/Tenant。
- `[Bind]`、`BindProperty`、`TryUpdateModel`、`UpdateModel`。
- DTO 与 Entity 是否混用。
- `ModelState`、Overposting、`UserId`、`Role`、`IsAdmin` 是否可被请求赋值。
- `AsNoTracking`、全局查询过滤器和多租户过滤器是否被绕过。

## CSRF

- MVC/Web API 是否启用 `ValidateAntiForgeryToken` 或全局 AutoValidateAntiforgeryToken。
- ASP.NET Core 是否配置 `AddAntiforgery`、`UseAntiforgery`、`IAntiforgery`。
- Cookie 认证是否与状态变更接口配合 CSRF 防护。
- SameSite 不能替代完整 CSRF 证据，必须检查实际 token。
- API 使用 Bearer Token 时仍检查浏览器存储和 CORS 组合风险。

## CORS

检查：

- `AddCors`、`UseCors`、`WithOrigins`、`AllowAnyOrigin`。
- `AllowCredentials` 与任意来源组合。
- 动态 Origin 回显、正则和子域匹配。
- Preflight 与普通请求的策略是否不一致。

