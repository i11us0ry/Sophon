---
name: dotnet-legacy-webforms-audit
description: >-
  ASP.NET WebForms 与传统 IIS 应用审计。覆盖 ViewState、MachineKey、Request Validation、Event Validation、ASHX、ASMX、WCF、Session、自定义错误和 IIS 配置。
metadata:
  tags: [dotnet, webforms, iis, legacy]
---

# ASP.NET WebForms 与传统 IIS 审计

## 入口

- `.aspx`、`.ascx`、`.master`、`.ashx`、`.asmx`、`.svc`。
- `Page_Load`、`OnInit`、`OnPreRender`、事件处理。
- `WebMethod`、WCF OperationContract、HTTP Handler。
- `Global.asax`、HTTP Module、HttpHandler。

## ViewState

检查：

- `EnableViewState`、`ViewStateMode`。
- `EnableViewStateMac`。
- `ViewStateEncryptionMode`。
- `machineKey` 的 validationKey、decryptionKey、算法。
- 是否跨机器共享密钥。
- 是否将敏感数据写入 ViewState。

缺少部署配置时标记 `ENV_DEPENDENT`。

## 输入验证

- `ValidateRequest`、`RequestValidationMode`。
- `ValidateRequest="false"`。
- `Request.Unvalidated`。
- `EventValidation`、`EnableEventValidation`。
- 富文本、上传和 JSON 接口的风险例外。

## 鉴权与会话

- Forms Authentication、Windows Authentication。
- `AuthorizeRequest`、web.config location 规则。
- Session、Cookie、MachineKey 和注销。
- 角色和资源所有权检查。

## 文件与 Handler

- `Response.WriteFile`、`Server.MapPath`、`Path.Combine`。
- `FileUpload`、`HttpPostedFile`。
- `Response.ContentType`、下载文件名和路径。
- ASHX 是否绕过 MVC/WebForms 鉴权。

## IIS 与配置

- `web.config`、`applicationHost.config`。
- `customErrors`、`httpErrors`。
- handler/module 顺序。
- 静态文件、目录浏览、请求过滤、默认文档。
- ASP.NET 版本和应用程序池身份。

## 输出

必须记录：

- 页面或 Handler 入口。
- 视图状态和密钥依赖。
- 输入验证和鉴权链路。
- 文件、行号和相关配置。
- 部署环境依赖。
- 状态、置信度和修复。

## 禁止

不启动 IIS，不发送 WebForms 请求，不生成或执行 ViewState/反序列化 payload。
