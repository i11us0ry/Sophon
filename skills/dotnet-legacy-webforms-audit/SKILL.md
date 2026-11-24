---
name: dotnet-legacy-webforms-audit
description: >-
  ASP.NET WebForms 与传统 IIS 应用审计。覆盖 ViewState、MachineKey、Request Validation、Event Validation、ASHX、ASMX、WCF、Session、自定义错误和 IIS 配置。
metadata:
  tags: [dotnet, webforms, iis, legacy]
---

# ASP.NET WebForms 与传统 IIS 审计

## 适用场景

适合已确认是 WebForms、ASHX、ASMX、WCF 或传统 IIS 应用，需要结合页面生命周期、ViewState、MachineKey、请求验证、鉴权和部署配置判断风险。

## 判断提示

`.aspx`、Handler 或 ViewState 字段本身只是线索。缺少部署配置、MachineKey、IIS 规则或入口证据时，相关判断通常只能作为环境依赖或待验证结论。

## 核心判断

传统 ASP.NET 风险高度依赖运行时和部署上下文：ViewState 完整性、MachineKey 来源、请求验证例外、EventHandler 鉴权、Handler 路由和 IIS 配置必须共同解释。

## 证据标准

- 可确认：真实页面/Handler 入口、鉴权或验证缺口、部署配置和可观测安全效果证据闭合。
- 待验证：发现危险配置或代码模式，但 MachineKey、IIS、应用池、路由或实际响应尚未确认。
- 判为否：配置可靠、入口不可达、鉴权覆盖生效，或风险只属于默认配置说明。

## 决策树

- 确认应用类型与入口：关联页面、Handler、Module 和路由。
- 检查鉴权与验证：定位 web.config、AuthorizeRequest、EventValidation 和 RequestValidation。
- 检查 ViewState：确认启用状态、MAC、加密和 MachineKey 部署来源。
- 检查文件与 Handler：追踪 MapPath、下载路径和 HTTP 方法。
- 缺少部署证据：标记环境依赖，不把静态猜测升级为已确认。

## 常见误判

- 看到 `__VIEWSTATE` 就认定可反序列化或可篡改。
- 忽略 MachineKey 是否自动生成、共享或由部署环境覆盖。
- 把 `ValidateRequest="false"` 直接等同于任意注入。
- ASHX/ASMX 存在就认为绕过鉴权，未检查 Module 和 location 规则。
- 启动 IIS、发送 WebForms 请求或执行 ViewState payload。

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

## 结果参考

- 页面或 Handler 入口。
- 视图状态和密钥依赖。
- 输入验证和鉴权链路。
- 文件、行号和相关配置。
- 部署环境依赖。
- 状态、置信度和修复。

