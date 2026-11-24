---
name: sophon-eino-demo
metadata:
  tags: [示例, eino, skill, 教学]
description: 满配示例技能包：SKILL.md + scripts/、references/、assets/ 等可选目录；验证 Eino skill 与 HTTP 包内路径。
---

# Sophon × Eino 满配技能演示

## 适用场景

适合验证 Sophon/Eino 的 Skill 包发现、摘要与全文读取、`##` 分块、包内资源路径和多 Agent 加载行为。

## 核心判断

这类验证关注“发现、解析、定位、读取、引用”是否闭环：索引是否出现正确元数据，分块是否匹配真实标题，`resource_path` 是否只读取包内预期文件，工具返回是否可追溯到包内容。

## 证据标准

- 可确认：索引、摘要/全文、section、resource 和实际返回内容一一对应，错误路径被拒绝。
- 待验证：索引可见但读取失败，或不同接口返回的元数据、分块和资源状态不一致。
- 判为否：包未被发现、资源越界被拒绝、内容与声明不符，或返回结果无法定位到包内文件。

## 决策树

- 先确认包被发现：检查名称、描述和文件计数。
- 再读取摘要和全文：核对 frontmatter 与章节内容。
- 检查 section：确认标题或短 id 映射稳定。
- 检查资源：验证合法相对路径可读、越界和不存在路径被拒绝。
- 只有索引成功：继续验证实际内容读取，不把登记等同于可用。

## 常见误判

- Skill 出现在列表中就直接判定全文与资源加载正常。
- 把示例 payload 的成功响应当成真实漏洞证据。
- 忽略 `SKILL.md` 标题变化导致 section 映射失效。
- 使用绝对路径或目录上跳测试后，把策略拒绝误判为工具故障。
- 只检查 HTTP 接口，忽略多 Agent 工具内的包加载差异。

## 概述

用于一次性验证：

- HTTP `GET /api/skills` 列表（`script_count`、`file_count`、`progressive` 等为推导/扫描结果）
- `GET /api/skills/sophon-eino-demo?depth=summary|full`
- `section=` 对应 `SKILL.md` 中 **`##` 标题**或 ASCII 标题的短 id（例如 `## Payload 样例` 常对应 `section=payload`）
- 多代理内 ADK **`skill`** 工具（及可选本机文件工具）读取包内相对路径资源
- Eino `FilesystemSkillsRetriever` 对包摘要、`##` 分块、脚本条目的检索

## 验证流程

1. **范围整理**：域名 / IP、接口列表和需要避免的影响。
2. **基线记录**：对约定资产做只读探测，保存时间戳与原始请求/响应摘要。
3. **分类测试**：按漏洞类型拆分任务。
4. **证据与报告**：每个发现附带复现步骤、影响、修复建议；敏感数据脱敏。
5. **收尾**：删除临时账号、清理测试数据、移交报告。

## Payload 样例

以下为 **教学占位**，实际使用时替换为目标上下文：

- SQLi 探测（错误型）：`"'`（观察是否触发数据库错误信息泄露）
- XSS 反射型（无害化）：`<script>alert(1)</script>` → 在靶场中应被编码或 CSP 拦截
- 路径穿越（只读验证）：`....//....//etc/passwd`

详细列表见 `scripts/payloads.txt`。

## references/ 与 assets/

用于验证非 `scripts/` 的子目录是否被同等对待：

| 路径 | 用途 |
|------|------|
| `references/citations.md` | 引用与 HTTP `resource_path` 测试说明 |
| `assets/README.txt` | 占位资源（可换成真实二进制做读文件上限测试） |

## 推荐工具链

| 阶段 | 工具示例 |
|------|-----------|
| 代理与重放 | Burp Suite、mitmproxy |
| 扫描与目录 | ffuf、nuclei |
| 记录 | Markdown + JSON 片段模板（见 `scripts/report-snippet.json`） |

## 清单与验证

- [ ] 已记录测试材料与观察窗口
- [ ] `scripts/` 下文件与正文引用一致
- [ ] Web 或 `GET /api/skills?...` 可核对索引；多代理会话内用 **`skill`** 工具按包加载以节省 token
- [ ] 需要细节时通过 **`skill`** 拉全文，或 HTTP `depth=full`、`section=<标题或短 id>`
- [ ] 需要脚本原文时通过本机文件工具或 HTTP `resource_path=scripts/check-env.sh`
- [ ] `resource_path=references/citations.md` 与 `resource_path=assets/README.txt` 可读取
