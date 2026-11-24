---
name: php-session-cookie-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 会话安全, cookie, jwt]
---

# PHP 会话与 Cookie 安全审计（php-session-cookie-audit）

分析 PHP 项目源码中认证会话相关的安全设置与实现逻辑，重点检测：
- session fixation
- cookie flags 缺失（HttpOnly/Secure/SameSite）
- JWT 校验缺陷（签名算法混淆、未校验 exp/iss/aud、弱密钥）
- remember-me/持久登录弱点（若存在）

## 适用场景

适合登录、登出、会话创建、Cookie 签发、JWT 验证和持久登录流程，需要判断会话标识能否被固定、伪造、复用或长期滥用。

## 不适用场景

Cookie 缺少某个安全属性不一定构成可利用漏洞，会话和 JWT 配置也要结合实际认证流程判断。公开静态资源的 Cookie、固定匿名会话和不承载认证状态的值通常不能按账号接管处理。

## 核心判断

会话安全的关键是认证状态是否与不可预测、可正确轮换和可失效的服务端凭证绑定。需要判断 session ID、JWT 或 remember token 的生成、验证、续期和注销是否形成完整生命周期。

## 证据标准

- 可确认：攻击者可控的会话输入或校验缺口实际导致认证绕过、会话接管或失效绕过，并有请求序列证据。
- 待验证：发现缺失轮换、弱属性或不完整 claim 校验，但实际攻击前提或认证影响尚未闭合。
- 判为否：凭证不可预测、登录后正确轮换、验证与注销生效，或问题只涉及低敏感 Cookie 的配置强化。

## 决策树

- 识别认证凭证：确认 Cookie、session、JWT 或 remember token 的实际用途。
- Session fixation：比较登录前后会话 ID、服务端状态和旧会话可用性。
- JWT：核对算法固定、签名密钥、claim、时钟和受众校验。
- Cookie flags：结合传输协议、脚本注入条件和数据敏感性判断影响。
- Logout：确认服务端会话、刷新令牌和持久化凭证是否全部失效。

## 常见误判

- 仅因缺少 `Secure` 或 `SameSite` 就宣称会话劫持。
- 登录后调用了轮换函数，但忽略旧 session ID 是否仍有效。
- 只解码 JWT payload，没有证明签名或 claim 校验缺口可用于伪造。
- 把前端不可读 Cookie 当成完全安全，忽略传输和 CSRF。
- 在验证会话固定或注销缺陷时影响其他真实用户会话。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-SESS-{序号}`

## 必检内容（可选）1. Session 初始化：
   - 是否在登录后 `session_regenerate_id`
   - 是否设置合理的超时、cookie 参数
2. Cookie flags：
   - `HttpOnly`、`Secure`、`SameSite` 是否明确设置
3. JWT：
   - decode/verify 使用的算法是否固定
   - 是否验证 `exp`/`nbf`/`iss`/`aud`
   - secret/公钥是否硬编码或读取不安全
4. 退出/失效：
   - logout 是否真正清除 session 与 token

## PoC 要求（可选）- 对 session fixation：给出请求序列（登录前固定 session id -> 登录后验证会话变化）
- 对 cookie flags：说明浏览器侧可见差异与危害（并给出示例 HTTP 响应头）
- 对 JWT：给出“签名算法/claim 校验缺失”的请求 PoC 框架（必须说明 payload 如何构造）

## 证据引用（有 trace 时）
每条会话与 Cookie 安全疑似风险有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **SESS 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_SESS_SESSION_INIT_REGEN`：登录后是否 `session_regenerate_id` 等会话固定防护证据
2. `EVID_SESS_COOKIE_FLAGS`：Cookie flags（HttpOnly/Secure/SameSite）设置证据
3. `EVID_SESS_JWT_VERIFY_CLAIMS`：JWT 签名算法固定与 exp/nbf/iss/aud 等 claim 校验证据
4. `EVID_SESS_LOGOUT_CLEAR`：logout 是否真正清除 session 与 token 的证据

## 条目记录建议

