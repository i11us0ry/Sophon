---
name: active-directory-attack
description: >-
  内网域攻击:BloodHound,Kerberoast,ADCS ESC1/ESC8,NTLM Relay,Coerce,DACL,DCSync,Zerologon/NoPac/PrintNightmare,mitm6,LLMNR,Linux内网。Use when attacking Active Directory, ADCS, NTLM relay, or internal domain.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 内网域攻击

## 适用场景

适合已确认存在 Active Directory、Kerberos、ADCS、SMB、LDAP 或域内主机，需要判断域权限路径和候选攻击面。

## 核心判断

先确认当前身份、凭据、机器可达性和域权限关系，再选择侦察、Kerberos、ADCS、Relay、Coerce、DACL 或域 CVE 路径。

## 证据标准

- 域路径需要域内对象、权限边、凭据或协议响应证据。
- 证书和 Relay 利用需要 CA、目标协议和权限证据。
- DCSync、域管凭据和持久化应结合权限、影响和回滚条件判断。
- 只有一个 CVE 名称或组件版本时保持候选。

## 决策树

- 域环境未知：先做最低影响的识别和路径验证。
- 有普通域凭据：检查 ACL、委派和攻击路径。
- 有 CA/ADCS：检查证书模板和注册权限。
- 有 Relay/Coerce 面：先证明协议和认证可达。
- 达到域权限证据：停止扩展并写回，不默认持久化。

## 常见误判

- 把 BloodHound 路径当成已利用路径。
- 把域内服务命中当成域管。
- 把 CVE 版本命中当成可直接打。
- 忽略 EDR、日志和业务影响。
- 仅凭域内对象名称认定 DCSync 或持久化可执行。

```
=== 内网域(2023+真实主战场) ===
侦察: BloodHound(SharpHound收集→攻击路径) | Kerberos: GetNPUsers(AS-REP)/GetUserSPNs(Kerberoast)
🚨ADCS(Certipy一把梭): certipy find -vulnerable | ESC1指定SAN申域管证书 | ESC8 relay到CA拿DC证书
🚨NTLM Relay(比PtH重要,PtH常被EDR拦): ntlmrelayx -t ldap--escalate-user / -t http CA --adcs(ESC8) / RBCD
🚨强制认证Coerce: PetitPotam(MS-EFSRPC)/coercer全协议喷/printerbug → 喂给relay
🚨DACL滥用: WriteDACL→给自己加DCSync | 影子凭据certipy shadow(GenericWrite即可,不改密码不留痕)
DCSync: secretsdump -just-dc → krbtgt hash→Golden Ticket
🚨一击致命域CVE(先测,命中直接域管): Zerologon(CVE-2020-1472,置空DC机器账户密码→DCSync) | NoPac(CVE-2021-42278/42287,机器账户改名申DC TGT) | PrintNightmare(CVE-2021-34527,后台打印RCE/加载恶意驱动) | EternalBlue(MS17-010,老SMBv1直RCE)
🚨IPv6/mitm6(默认双栈内网必打): mitm6劫持DHCPv6+DNS→WPAD→ntlmrelayx到LDAP/ADCS(比LLMNR更隐蔽,现代内网首选)
LLMNR/NBT-NS投毒: responder抓NetNTLMv2→hashcat破/relay
Linux内网: Redis未授权(CONFIG SET dir写SSH key) | NFS showmount | Docker 2375
```
