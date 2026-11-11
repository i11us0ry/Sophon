# 角色配置文件说明

本目录包含所有角色配置文件，每个角色定义了AI的行为模式与可用工具。

## 创建新角色

创建新角色时，请在 `roles/` 目录下创建 YAML 文件，格式如下：

**方式1：显式指定工具列表（推荐）**
```yaml
name: 角色名称
description: 角色描述
user_prompt: 用户提示词（追加到用户消息前，用于引导AI行为）
icon: "图标（可选）"
skills:
  - attack-surface-recon
  - pentest-verification
tools:
    # 添加你需要的工具...
    # ⚠️ 重要：建议包含以下核心内置 MCP 工具（漏洞与知识库）
    - record_vulnerability
    - list_knowledge_risk_types
    - search_knowledge_base
enabled: true
```

**方式2：不设置tools字段（使用所有已开启的工具）**
```yaml
name: 角色名称
description: 角色描述
user_prompt: 用户提示词（追加到用户消息前，用于引导AI行为）
icon: "图标（可选）"
skills:
  - attack-surface-recon
# 不设置tools字段，将默认使用所有MCP管理中已开启的工具
enabled: true
```

## ⚠️ 重要提醒：核心内置 MCP 工具

**如果设置了 `tools` 字段，请务必在列表中包含以下工具（至少这三项）：**

1. **`record_vulnerability`** - 漏洞管理工具，用于记录发现的漏洞
2. **`list_knowledge_risk_types`** - 知识库工具，列出可用的风险类型
3. **`search_knowledge_base`** - 知识库工具，搜索知识库内容

按需还可加入 WebShell、批量任务等其它内置或外部工具（以 MCP 管理中已启用的为准）。

**Skills（技能包）**：角色可通过 `skills` 字段绑定 `skills_dir` 下的技能包，会话中由内置 **`skill`** 工具按需加载。技能名称须为 `[a-zA-Z0-9_-]`，同名项会自动去重，单个角色最多绑定 50 个技能。

内置角色首次同步时使用 YAML 中的技能绑定；已存在的角色保留用户在角色管理页面修改后的技能绑定。

**注意**：如果不设置 `tools` 字段，系统会默认使用所有 MCP 管理中已开启的工具。为明确控制角色可用工具，建议显式设置 `tools` 字段。

## 角色配置字段说明

- **name**: 角色名称（必填）
- **description**: 角色描述（必填）
- **user_prompt**: 用户提示词，会追加到用户消息前，用于引导AI采用特定的测试方法和关注点（可选）
- **icon**: 角色图标，支持Unicode emoji（可选）
- **skills**: 技能包名称列表（可选）。技能目录必须位于配置的 `skills_dir` 下，且包含 `SKILL.md`
- **tools**: 工具列表，指定该角色可用的工具（可选）
  - **如果不设置 `tools` 字段**：默认会选中**全部MCP管理中已开启的工具**
  - **如果设置了 `tools` 字段**：只使用列表中指定的工具（建议至少包含上述核心内置工具）
- **enabled**: 是否启用该角色（必填，true/false）

## 示例

参考本目录下的其他角色文件，如 `渗透测试.yaml`、`Web应用扫描.yaml` 等。
