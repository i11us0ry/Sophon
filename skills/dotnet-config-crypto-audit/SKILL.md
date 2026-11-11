---
name: dotnet-config-crypto-audit
description: >-
  .NET / C# 配置与加密审计。覆盖 appsettings、web.config、secrets、JWT、Cookie、Identity、DataProtection、MachineKey、TLS、密码学、CORS、错误页和安全头。
metadata:
  tags: [dotnet, 配置, 加密, jwt, dataprotection]
---

# .NET 配置与加密审计

## 配置与秘密

检查：

- `appsettings*.json`、`web.config`、`app.config`。
- `.env`、User Secrets、Environment Variables。
- 连接字符串、JWT Key、OAuth secret、API key、证书密码。
- `AddUserSecrets`、Key Vault、DPAPI、配置提供器。
- 配置是否被静态文件中间件暴露。

密钥只记录路径和脱敏证据，不使用。

## JWT

检查：

- Issuer、Audience、SigningKey、Lifetime、ClockSkew。
- `ValidateIssuer`、`ValidateAudience`、`ValidateLifetime`、`ValidateIssuerSigningKey`。
- 算法是否固定，是否允许 `none` 或算法混淆。
- Token 是否在 Cookie、LocalStorage 或 Session 中。
- 注销、刷新和撤销机制。

## Cookie 与 Identity

- `HttpOnly`、`Secure`、`SameSite`。
- Cookie 名、Path、Domain、Expiration。
- ASP.NET Identity 密码策略、锁定、2FA、恢复流程。
- SlidingExpiration、Session 固定和重新登录。

## DataProtection / MachineKey

- DataProtection key 是否持久化、共享和保护。
- `SetApplicationName` 是否一致。
- Key 存储目录权限。
- WebForms `machineKey` 是否弱密钥、自动生成或跨环境共享。
- ViewState 和 Cookie 是否依赖 MachineKey。

## TLS 与证书

- `ServicePointManager`、`HttpClientHandler.ServerCertificateCustomValidationCallback`。
- 是否关闭证书验证。
- TLS 版本、HSTS、HTTPS redirection。
- 证书 pinning、自定义信任链和代理。

## 密码学

- MD5、SHA1、无 salt 哈希。
- AES/ECB、固定 IV、错误 key 派生。
- `Random` 用于安全令牌。
- `RNGCryptoServiceProvider`、`RandomNumberGenerator` 使用是否正确。
- HMAC、签名比较是否使用固定时间比较。

## 错误与安全头

- `UseDeveloperExceptionPage` 是否在生产启用。
- `customErrors`、`httpErrors`、详细堆栈。
- CSP、HSTS、X-Content-Type-Options、Frame-Options。
- CORS 与 Cookie 凭据组合。

## 输出

每条发现记录配置来源、环境覆盖、运行时影响、文件、行号和相关入口。无法确定部署环境时标记 `ENV_DEPENDENT` 或 `NEEDS_VALIDATION`。
