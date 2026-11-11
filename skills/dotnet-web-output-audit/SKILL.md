---
name: dotnet-web-output-audit
description: >-
  .NET / C# Web 输出审计。覆盖 Razor、Blazor、MVC、Html.Raw、MarkupString、HTML/JS 编码、XSS、开放重定向、CRLF、响应头、Cookie 和 MIME 类型风险。
metadata:
  tags: [dotnet, xss, razor, blazor]
---

# .NET Web 输出审计

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

## 输出

每条发现必须包含：

- 输出 Sink。
- 编码/净化逻辑。
- 上下文类型。
- Source 到 Output 的数据流。
- 浏览器侧利用条件。
- 文件、行号、类和方法。
- 状态、置信度和修复。

## 禁止

不向浏览器发送 payload，不启动前端、不执行 JavaScript。
