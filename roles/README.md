# Task Profile 配置文件说明

本目录中的 YAML 是可选任务模板，不是 Agent 身份、权限或工具配置。

系统 Agent 的身份、执行模式、工具权限、技能读取权限和授权边界由平台固定逻辑决定。Task Profile 只提供领域方法、关注点和推荐方法包。

## 创建任务模板

```yaml
name: 任务模板名称
description: 任务模板说明
user_prompt: |
  适用场景：说明该模板适用的任务类型。
  方法建议：
  1. 说明值得优先检查的方向。
  2. 说明数据流、证据和误判边界。
  3. 说明没有思路时可按需读取哪些全局方法包。
  该模板只提供方法参考，不改变系统 Agent 身份、工具权限、执行模式或授权范围。
icon: "图标（可选）"
skills:
  - attack-surface-recon
  - pentest-verification
enabled: true
```

## 字段说明

- `name`: 任务模板名称，必填。
- `description`: 任务模板说明。
- `user_prompt`: 方法提示，供 Main Agent 和 Planner 参考，不得写成业务角色身份或权限声明。
- `icon`: 展示图标。
- `skills`: 推荐方法包列表，不构成白名单、必读项或权限边界。
- `enabled`: 是否允许新会话选择该模板。
- `default_mode`: 仅为旧 YAML 兼容保留，不参与运行模式计算。

## Skill 访问

Skill 是全局方法包。任何会话和 Worker 都可以通过 `read_skill` 按需读取已存在的合法方法包，不受 Task Profile 绑定关系限制。

内置 Task Profile 首次同步时使用 YAML 中的推荐方法包；已存在的模板继续保留用户在 Agent 管理页面修改后的配置。旧版身份型内置 Prompt 会在检测到未修改的默认内容时迁移为方法包。
