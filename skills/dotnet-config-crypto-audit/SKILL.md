---
name: dotnet-config-crypto-audit
description: >-
  .NET / C# 配置与加密审计。覆盖 appsettings、web.config、secrets、JWT、Cookie、Identity、DataProtection、MachineKey、TLS、密码学、CORS、错误页和安全头。
metadata:
  tags: [dotnet, 配置, 加密, jwt, dataprotection]
---

# .NET 配置与加密审计

## 适用场景

适合检查配置、密钥、JWT、Cookie、Identity、DataProtection、MachineKey、TLS、密码学和错误页，并判断是否存在实际安全问题。

## 不适用场景

单个弱配置或算法名称不必然构成可利用漏洞。无法确定部署环境、入口或影响路径时应标记环境依赖或待验证。

## 核心判断

配置审计要区分“配置存在”与“该配置在运行环境中生效且可被利用”。需要结合环境覆盖、入口、凭据形态和安全影响。

## 证据标准

- 配置发现需要来源文件、环境覆盖和运行时加载证据。
- 密钥只保留路径、类型和脱敏证据，不读取或使用秘密。
- JWT、Cookie 和 MachineKey 需要结合验证逻辑和实际入口。
- TLS 和密码学问题需要说明攻击条件和影响，不只列算法名。

## 决策树

- 配置存在：检查环境覆盖和是否真正加载。
- 秘密暴露：检查可通过哪个入口访问以及是否仍有效；不实际使用秘密。
- JWT/Cookie 缺陷：检查算法、验证开关、凭据传递和会话影响。
- 弱密码学：检查用途、攻击者控制和是否保护敏感数据。
- 部署环境未知：标记 ENV_DEPENDENT，不升级为 confirmed。

## 常见误判

- 把 appsettings 中的占位值当成生产密钥。
- 把 MD5/SHA1 出现当成密码存储漏洞。
- 把关闭证书验证直接当成可利用中间人。
- 把宽松 CORS 和 Cookie 同时出现直接当成数据读取。
- 把开发环境错误页当成生产暴露。

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

