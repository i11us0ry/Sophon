---
name: initial-access-phishing
description: >-
  初始访问/钓鱼/社工:凭据喷洒,AiTM,设备码,OAuth同意钓鱼,载荷,vishing。Use when needing initial access, phishing, AiTM, device code, or social engineering.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 初始访问 / 钓鱼 / 社工

## 适用场景

## 核心判断

先确认目标人群、账户锁定策略、邮件网关和业务时段，再选择影响最小、可审计的验证方式。

## 证据标准

- 凭据命中需要避免锁定并保留最小验证证据。
- 钓鱼验证可准备目标范围、名单和停止条件。
- 设备码/OAuth 同意可证明实际访问影响，并注意 token 保存周期。

## 决策树

- 只有邮箱格式：先做 OSINT，不发送邮件。
- 有测试名单：选择最小邮件和单个交互验证。
- 有账户锁定风险：停止喷洒并改用低影响验证。
- 获取到会话或 token：证明影响后立即停止并安全处置。
- 无目标名单或业务上下文：先补充侦察信息。

## 常见误判

- 把泄露库账号当成当前有效。
- 为验证而批量投放邮件。
- 忽略对真实员工和供应商的影响。
- 获取 token 后继续扩大访问。
- 把邮件打开率当成漏洞成立。

```
=== 初始访问/钓鱼/社工(外部进内部第一跳,打点前的打点) ===
凭据喷洒: 弱密码(Season+Year!/公司名123)喷全体账号(每账号1-2次避锁定) | 来源:泄露库/OSINT邮箱格式(f.last@)/默认凭据
AiTM钓鱼(绕MFA): evilginx3/Modlishka反代真站→中间人偷session cookie+token(绕MFA) | phishlet配域名+证书
设备码钓鱼(Azure/M365): device code flow→诱导受害者输码→拿access/refresh token(无需密码/MFA) | TokenTactics/AADInternals
钓鱼载荷: gophish发信+落地页 | 载荷 lnk/iso/宏/HTA/OneNote | 绕网关:密码zip/云盘链接/HTML走私
OAuth同意钓鱼(illicit consent): 恶意App请求过度scope(Mail.Read/offline_access)→受害者同意→长期访问令牌
社工前戏: OSINT组织架构/供应商/口令习惯(LinkedIn/招聘/GitHub) | pretext借口(IT支持/供应商/HR) | vishing(deepfake声音)
→ 初始access落地即转 `redteam-opsec`(别一进门就被EDR抓), 拿到的能力进 `capability-primitive-search` 凑链
```
