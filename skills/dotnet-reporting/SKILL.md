---
name: dotnet-reporting
description: >-
  .NET 代码审计报告与证据复核。用于汇总路由、鉴权、数据流、专项 Sink、配置、依赖和 WebForms 结果，输出 findings.json、覆盖矩阵、待补证风险池和质量报告。
metadata:
  tags: [dotnet, 报告, findings, 证据]
---

# .NET 代码审计报告

## 输入

- 项目侦察和路由鉴权矩阵。
- 数据流追踪结果。
- 各专项漏洞发现。
- 依赖和配置风险。
- 未闭合、失败和延期项。

## 去重

按以下组合去重：

- 文件、方法和行号。
- Source、Sink 和漏洞类型。
- 路由或服务入口。
- 相同根因的多个调用点。

不要合并根因不同但位置相同的发现。

## 必须输出

```text
{output_path}/findings.json
{output_path}/quality_report.md
```

报告结构：

1. 审计范围、限制和授权说明。
2. 项目框架、目标运行时和部署形态。
3. 路由与鉴权覆盖统计。
4. 漏洞总览和严重度统计。
5. 漏洞详情。
6. 配置和依赖风险。
7. 候选利用链。
8. Trace 未闭合和待补证风险池。
9. 审计面覆盖矩阵。
10. 修复优先级和回归建议。

## Finding 字段

- `id`
- `title`
- `type`
- `severity`
- `cvss`
- `status`
- `confidence`
- `route_or_entry`
- `source`
- `sink`
- `file`
- `line`
- `symbol`
- `data_flow`
- `control_conditions`
- `evidence`
- `impact`
- `fix`
- `unverified`

## 覆盖矩阵

每个技能和审计面标记：

- `EXECUTED`
- `NOT_APPLICABLE`
- `DEFERRED`

必须写触发依据或否定证据，不能留空。

## 候选利用链

- 只能消费已有发现。
- 以最弱环节决定链路状态。
- 缺证据时写 `NEEDS_VALIDATION`。
- 不补造运行时结果、截图或利用效果。

## 安全

报告中的 PoC 只作为静态验证模板。不得包含真实凭据、Cookie、连接字符串或可直接使用的攻击流量。
