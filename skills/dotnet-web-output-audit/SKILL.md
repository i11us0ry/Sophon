---
name: dotnet-web-output-audit
description: >-
  .NET / C# Web 输出审计。覆盖 Razor、Blazor、MVC、Html.Raw、MarkupString、HTML/JS 编码、XSS、开放重定向、CRLF、响应头、Cookie 和 MIME 类型风险。
metadata:
  tags: [dotnet, xss, razor, blazor]
---

# .NET Web 输出审计

## 适用场景

适合 Razor、Blazor、MVC、响应头、Cookie、重定向和文件响应中，用户可控值进入浏览器解释上下文，需要判断输出编码和安全影响。

## 不适用场景

看到 `Html.Raw`、`MarkupString`、`Redirect` 或响应头 API 不能直接确认漏洞。固定内容、正确上下文编码、可靠净化、本地 URL 限制，或浏览器不会解释的输出应降级或判为否。

## 核心判断

Web 输出风险取决于 source、sink 和解释上下文是否同时闭合。HTML、属性、JavaScript、JSON、CSS、URL、Header 和文件 MIME 需要不同处理，编码函数必须与其上下文匹配。

## 证据标准

- 可确认：用户控制映射、输出 sink、编码/净化缺口和浏览器或客户端解释效果证据闭合。
- 待验证：发现 raw 输出或响应头写入，但 source、上下文、净化、CSP 或实际响应尚未确认。
- 判为否：输出为固定值、编码与上下文匹配、本地 URL 校验可靠，或浏览器不会执行/导航到危险目标。

## 决策树

- 找到输出 sink：确认 HTML 编码、Markup、Header、Cookie、Redirect 或文件响应类型。
- 追踪 source：判断用户输入是否保留危险字符和结构。
- 判断上下文：核对同一值在 HTML、JS、URL、CSS 和属性中的编码路径。
- 检查浏览器条件：评估 CSP、nosniff、Content-Type 和导航行为。
- 只有静态 raw API：保留候选，不发送 payload 或执行 JavaScript。

## 常见误判

- `Html.Raw` 或 `MarkupString` 存在就认定 XSS。
- 使用 HTML 编码处理 JavaScript 字符串或 URL 上下文。
- 只检查参数名就确认开放重定向，忽略最终 Location。
- 只过滤 `%0d%0a`，不检查实际 Header 解析后的控制字符。
- 文件可下载就认定 MIME 嗅探或脚本执行，忽略 Content-Type 与 nosniff。

## XSS

检查：

- Razor 是否输出 `Html.Raw`。
- `MvcHtmlString`、`HtmlString`、`IHtmlContent`。
- Blazor `MarkupString`、`builder.AddMarkupContent`。
- `Content(value, "text/html")` 和文件响应。
- JavaScript 字符串、JSON、CSS、URL 和 HTML 属性上下文。
- `@Html.Encode`、`HtmlEncoder`、`JavaScriptEncoder`、`UrlEncoder`。

判断：

- Razor 默认编码通常是防护。
- 编码必须匹配输出上下文。
- 同一值进入 HTML、JavaScript、URL 和 CSS 时需不同编码。
- `Html.Raw` 只有在值可控且未净化时才形成闭环。

## Blazor

- `MarkupString` 的输入来源。
- `NavigationManager.NavigateTo` 是否允许外部 URL。
- JS interop 是否将用户值写入 DOM。
- `IJSRuntime.InvokeAsync` 调用的前端方法是否使用 `innerHTML`。

## 开放重定向

- `Redirect`、`LocalRedirect`、`RedirectToAction`、`RedirectToPage`。
- 返回 URL、`returnUrl`、`next`、`continue`。
- 是否只允许本地路径。
- `Url.IsLocalUrl` 是否被正确使用。

## CRLF 与响应头

- `Response.Headers`、`Response.Cookies.Append`。
- `Content-Disposition` 文件名。
- `Location`、`Set-Cookie` 和自定义 Header。
- 是否过滤 `\r`、`\n` 和非法控制字符。

## MIME 与内容嗅探

- 用户上传内容是否以 HTML、SVG、XML 或脚本 MIME 返回。
- 是否设置 `X-Content-Type-Options: nosniff`。
- CSP、frame-ancestors 和 origin 隔离。

