---
name: source-code-hunting
description: >-
  源码狩猎:.git泄露,危险函数grep,JS RC4解混淆,semgrep/CodeQL,trufflehog,patch diff,供应链/CI。Use when hunting source leaks, secrets, JS deobfuscation, or supply-chain issues.
metadata:
  tags: [渗透测试, penetration-testing, 红队]
---

## 适用场景

适合发现源码、备份、前端 bundle、Git 历史、密钥线索、危险函数和供应链入口，需要判断其真实影响。

## 核心判断

源码狩猎先判断材料是否属于目标、是否可读、是否包含有效秘密或可利用逻辑，再回溯入口和影响。

## 证据标准

- 源码泄露需要可访问路径和内容证据。
- 密钥需要状态、权限、有效性和适用范围。
- 危险函数需要数据流和可达性。
- Patch diff 和供应链线索需要版本、补丁和影响映射。

## 决策树

- 获取源码或 bundle：检查入口、配置、密钥和危险调用。
- 发现秘密：验证来源和有效性边界，避免使用真实凭据。
- 发现危险函数：转入数据流或代码审计。
- 发现历史提交：检查已删除文件和补丁差异。
- 只有公开字符串：保留线索，不写 confirmed。

## 常见误判

- 把公开前端代码都当成源码泄露。
- 把格式像 key 的字符串当成有效凭据。
- 把危险函数出现在依赖中当成业务漏洞。
- 忽略版本和运行时入口。
- 使用发现的秘密扩大影响。

## 源码狩猎

```
=== 源码狩猎 ===
.git泄露: git-dumper → git log -p --all(已删敏感文件) | .svn/.DS_Store/composer.lock
危险函数grep: exec/system/eval/unserialize/pickle.loads/render/curl_exec + 硬编码密钥(sk-/ghp_/BEGIN RSA)
JS混淆破解(RC4+base64字符串数组模式): 1)提取字符串数组(var a0G=[...]) 2)找解码函数(a0m(idx,key)→RC4解密+base64) 3)找rotation IIFE(目标偏移量) 4)Node.js重建解码器批量解码全部字符串→得到明文变量名/API路径/配置
  UniApp特征: app-service.js(业务逻辑,常800KB+混淆) + zlsioh.dat(加密配置,native .so解密) + dcloud_uniplugins.json(插件清单)
静态扫描: semgrep --config=auto 快扫 / CodeQL建库写query (taint求解+变体分析方法论见 `zero-day-discovery`)
Secrets深挖: trufflehog/gitleaks 扫git全历史+docker镜像层+npm/PyPI tarball+前端bundle(--only-verified区分死活密钥)
框架Patch Diff: clone前后版本 diff → 修了什么=漏洞在哪 | 依赖链: composer.json/npm audit/pip-audit
供应链/CI: 依赖混淆(内部包名抢注公共registry) | GHA命令注入${{github.event.issue.title}} | self-hosted runner接管 | .npmrc/.pypirc凭据
```
