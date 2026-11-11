<div align="center">
  <img src="./frontend/img/icon.png" width="120" alt="Sophon" />
  <h1>Sophon</h1>
  <p><strong>面向授权安全测试的智能 Agent 工作台</strong></p>

  ![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)
  ![Vue](https://img.shields.io/badge/Vue-3.5-42B883?logo=vuedotjs&logoColor=white)
  ![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)
  ![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
  ![Status](https://img.shields.io/badge/status-pre--release-orange)
</div>

<p align="center">
  <a href="#zh-cn">简体中文</a>
  |
  <a href="#english">English</a>
</p>

<details id="zh-cn" name="language" open>
<summary><strong>简体中文</strong></summary>

## 项目简介

Sophon 是一个面向授权安全测试、代码审计和攻防演练的智能 Agent 工作台。平台将角色、技能、项目上下文、工具执行、证据、漏洞审核、复测和报告输出整合到同一工作流中。

它支持两种运行模式：

- **单 Agent 模式**：当前角色直接使用其提示词、技能和项目上下文执行任务。
- **多 Agent 模式**：主 Agent 负责协调，Planner 生成可验证假设，Worker 在受限范围内执行并写回证据。

Sophon 的目标不是让模型无限调用扫描器，而是让每次测试具备明确范围、真实证据、审核记录和可复现结论。

> [!WARNING]
> Sophon 仅允许用于本组织拥有或控制的系统，以及已获得目标所有者明确书面授权的安全测试、代码审计和防御演练。严禁用于未授权访问、扫描、利用、干扰、数据收集或数据留存。使用者对全部操作及后果负责。

## 核心能力

| 能力 | 说明 |
|---|---|
| 单 Agent | 直接使用当前角色、技能和项目上下文执行任务 |
| 多 Agent | 主 Agent、Planner、Worker 和受限子 Agent 协同执行 |
| 角色与技能 | 角色定义业务身份；技能提供方法和检查项，按需加载正文 |
| 项目上下文 | 项目、资产、事实、测试假设、漏洞、会话和攻击路径统一关联 |
| 证据驱动 | 漏洞需关联工具输出、请求响应、源码位置或可复现步骤 |
| 安全边界 | Mission Policy、授权范围、路径限制、人工审批和资源预算 |
| MCP 与本地工具 | 支持 MCP 服务、工具白名单、YAML 工具和本地命令环境 |
| 代码审计 | 内置 Java、PHP、.NET、二进制和 App 逆向相关能力 |
| 漏洞治理 | 漏洞审核、状态流转、复测、证据引用和报告导出 |
| 审计与 RBAC | 登录审计、工具执行记录、Agent 状态、Token 用量和路由级权限 |
| 中英文界面 | 简体中文与英文界面，支持明暗主题 |

## 系统架构

```text
浏览器
  │
  ▼
Nginx
  ├── 静态前端资源
  ├── /api 反向代理
  └── SSE 流式响应
        │
        ▼
Go API / Agent Runtime
  ├── SQLite
  ├── Workspace 与附件
  ├── MCP Client
  ├── 本地工具执行器
  └── LLM / Embedding API
```

## Agent 与技能上下文

Sophon 不会在每轮对话中加载全部技能正文。默认只注入：

- 当前角色提示词
- 已绑定技能名称
- 技能摘要
- 项目、资产、事实和记忆
- Mission Policy

只有模型需要具体执行步骤时，才通过 `read_skill` 加载技能正文。

```text
用户选择角色
├── 角色提示词 ─────────────────┐
└── 绑定技能列表
    └── 技能名称与摘要 ─────────┤
                                ├── 初始上下文 → LLM
项目、资产、事实 ───────────────┤
会话摘要与长期记忆 ─────────────┤
Mission Policy ─────────────────┘

LLM ── 需要完整步骤时 ──> read_skill ──> 技能正文
```

## 运行要求

### 主机安装

- Debian、Ubuntu、Kali Linux、CentOS/RHEL 系
- root 或 sudo 权限
- 建议至少 4 核 CPU、8 GB 内存
- 可访问 LLM API，或使用 Mock 模式

### Docker 安装

- Docker 24+
- 建议至少 4 核 CPU、8 GB 内存
- 扫描类工具需要 `NET_RAW` 能力

## 部署方式

部署只支持以下两种方式。

### 1. 主机安装：install.sh

```bash
chmod +x install.sh
sudo ./install.sh
```

安装脚本会自动处理：

- Ubuntu、Debian、Kali、CentOS/RHEL 系统依赖
- 国内 APT/YUM 软件源
- Go、Node.js、pnpm
- Go 国内模块代理
- Python 国内 PyPI 镜像
- 后端、前端和工具运行器构建
- systemd 服务创建与启动

常用参数：

```bash
sudo ./install.sh --node-mirror aliyun
sudo ./install.sh --go-mirror auto --pip-index auto
sudo ./install.sh --no-start
```

### 2. Docker 安装：install-docker.sh

```bash
chmod +x install-docker.sh
./install-docker.sh
```

脚本会拉取 Kali 基础镜像，创建新容器，安装依赖并构建 Sophon。

常用参数：

```bash
./install-docker.sh --name sophon --host-port 8080
./install-docker.sh --dry-run
./install-docker.sh \
  --image docker.m.daocloud.io/kalilinux/kali-rolling:latest \
  --node-image docker.m.daocloud.io/library/node:20-bookworm-slim
```

默认持久化目录：

```text
~/.sophon/docker
```

## 配置

配置优先级：

```text
程序默认值 < config.yml < 环境变量
```

常用环境变量：

| 变量 | 说明 |
|---|---|
| `SOPHON_CONFIG` | 配置文件路径 |
| `SOPHON_HOST` | 后端监听地址 |
| `SOPHON_PORT` | 后端监听端口 |
| `SOPHON_DATA_DIR` | 数据库、附件和工作区根目录 |
| `SOPHON_ADMIN_USERNAME` | 初始管理员用户名 |
| `SOPHON_ADMIN_PASSWORD` | 初始管理员密码 |
| `SOPHON_COOKIE_SECURE` | HTTPS 环境应设置为 `true` |
| `SOPHON_LLM_BASE_URL` | OpenAI 兼容 API 地址 |
| `SOPHON_LLM_API_KEY` | LLM API Key |
| `SOPHON_LLM_MODEL` | LLM 模型名 |
| `SOPHON_EMBEDDING_BASE_URL` | Embedding API 地址 |
| `SOPHON_EMBEDDING_API_KEY` | Embedding API Key |
| `SOPHON_HITL_ENABLED` | 是否启用人工审批 |

完整配置见 [`config.example.yml`](./config.example.yml)。

## 首次登录

- 默认用户名由 `auth.bootstrap_admin.username` 或 `SOPHON_ADMIN_USERNAME` 决定。
- 初始密码来自 `auth.bootstrap_admin.password`、`SOPHON_ADMIN_PASSWORD` 或自动生成的密码文件。
- 自动生成的密码文件位于数据目录下的 `bootstrap_admin_password.txt`。
- 首次登录后应立即修改密码，并删除初始密码文件。

## 安全与审计

- 生产环境必须使用 HTTPS，并设置 `SOPHON_COOKIE_SECURE=true`。
- 服务应部署在受信任网络或带认证的反向代理之后。
- MCP 服务、自定义工具和高风险命令启用前必须审核。
- 工作区、附件、工具输出和漏洞证据均应视为敏感数据。
- 定期轮换 LLM、Embedding 和其他第三方凭据。
- 定期备份 SQLite 数据库、`config.yml`、工作区、附件和角色技能配置。

Sophon 不保证完整漏洞覆盖。模型输出必须由具备资质的安全人员复核，不能直接作为漏洞定论或修复依据。

## 安全声明

Sophon 仅允许用于本公司、本组织拥有或明确控制的系统，以及获得目标所有者书面授权的安全测试、代码审计和防御演练。

使用者必须提前确认授权主体、目标范围、时间窗口、允许技术、数据处理方式和应急联系人。任何超出书面授权的访问、扫描、利用、干扰、收集或留存均被禁止。

在适用法律允许的最大范围内，项目作者、贡献者和维护者不对误用、未授权测试、违法行为、配置错误、工具缺陷、模型输出、数据泄露、业务中断、财产损失或第三方索赔承担责任。

本声明不构成法律意见，也不能替代正式授权文件或专业法律建议。

## 许可证

仓库当前未包含项目级 `LICENSE` 文件。除版权所有者书面授权外，保留所有权利。第三方工具和依赖遵循各自许可证。

</details>

<details id="english" name="language">
<summary><strong>English</strong></summary>

## Overview

Sophon is a security Agent workbench for authorized security testing, code review, and defensive exercises. It combines roles, skills, project context, tool execution, evidence, vulnerability review, retesting, and reporting in one workflow.

It supports two execution modes:

- **Single-Agent mode**: the selected role executes directly with its prompt, skills, and project context.
- **Multi-Agent mode**: the main Agent coordinates work, the Planner creates verifiable hypotheses, and Workers execute within restricted scopes and write back evidence.

Sophon is designed to make every test scoped, traceable, evidence-backed, reviewable, and auditable instead of allowing unbounded model-driven scanning.

> [!WARNING]
> Sophon may only be used against systems owned or controlled by your organization, or for security testing, code review, and defensive exercises with explicit written authorization from the target owner. Unauthorized access, scanning, exploitation, disruption, collection, or retention is prohibited. Users are responsible for all actions and consequences.

## Highlights

| Capability | Description |
|---|---|
| Single Agent | Executes with the selected role, skills, and project context |
| Multi Agent | Main Agent, Planner, Workers, and restricted sub-Agents |
| Roles and skills | Roles define identity; skills provide methods and checklists |
| Project context | Projects, assets, facts, hypotheses, findings, and graphs |
| Evidence-driven findings | Tool output, HTTP evidence, source locations, and reproduction steps |
| Security boundaries | Mission Policy, authorized scope, path restrictions, HITL, and budgets |
| MCP and local tools | MCP servers, allowlists, YAML tools, and local command execution |
| Code review | Java, PHP, .NET, binary analysis, and mobile reverse engineering |
| Vulnerability governance | Review, status, retest, evidence references, and report export |
| Audit and RBAC | Audit logs, tool execution records, token usage, and route permissions |
| Bilingual UI | Simplified Chinese and English with light and dark themes |

## Architecture

```text
Browser
  │
  ▼
Nginx
  ├── Static frontend assets
  ├── /api reverse proxy
  └── SSE streams
        │
        ▼
Go API / Agent Runtime
  ├── SQLite
  ├── Workspaces and attachments
  ├── MCP client
  ├── Local tool runner
  └── LLM / Embedding APIs
```

## Agent and Skill Context

Sophon does not load every skill body on every turn. The initial context contains only:

- The active role prompt
- Bound skill names
- Skill summaries
- Project, asset, fact, and memory context
- Mission Policy

Full skill instructions are loaded through `read_skill` only when needed.

```text
User selects a role
├── Role prompt ─────────────────┐
└── Bound skills
    └── Skill names + summaries ─┤
                                 ├── Initial context → LLM
Projects / assets / facts ───────┤
Conversation summaries / memory ─┤
Mission Policy ──────────────────┘

LLM ── when full steps are needed ──> read_skill ──> Skill body
```

## Requirements

### Host installation

- Debian, Ubuntu, Kali Linux, or CentOS/RHEL-family systems
- root or sudo access
- 4 CPU cores and 8 GB RAM recommended
- Access to an LLM API, or Mock mode

### Docker installation

- Docker 24+
- 4 CPU cores and 8 GB RAM recommended
- `NET_RAW` for tools that require raw sockets

## Deployment

Sophon supports the following two deployment methods.

### 1. Host installation: install.sh

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer handles:

- System dependencies for supported Linux distributions
- Domestic APT/YUM repositories
- Go, Node.js, and pnpm
- Domestic Go module proxy
- Domestic Python package indexes
- Backend, frontend, and tool-runner builds
- systemd service creation and startup

Common options:

```bash
sudo ./install.sh --node-mirror aliyun
sudo ./install.sh --go-mirror auto --pip-index auto
sudo ./install.sh --no-start
```

### 2. Docker installation: install-docker.sh

```bash
chmod +x install-docker.sh
./install-docker.sh
```

The script pulls a Kali base image, creates a new container, installs dependencies, and builds Sophon.

Common options:

```bash
./install-docker.sh --name sophon --host-port 8080
./install-docker.sh --dry-run
./install-docker.sh \
  --image docker.m.daocloud.io/kalilinux/kali-rolling:latest \
  --node-image docker.m.daocloud.io/library/node:20-bookworm-slim
```

Default persistent directory:

```text
~/.sophon/docker
```

## Configuration

Configuration precedence:

```text
defaults < config.yml < environment variables
```

Common environment variables:

| Variable | Purpose |
|---|---|
| `SOPHON_CONFIG` | Configuration file path |
| `SOPHON_HOST` | Backend listen address |
| `SOPHON_PORT` | Backend listen port |
| `SOPHON_DATA_DIR` | Database, attachments, and workspace root |
| `SOPHON_ADMIN_USERNAME` | Bootstrap administrator username |
| `SOPHON_ADMIN_PASSWORD` | Bootstrap administrator password |
| `SOPHON_COOKIE_SECURE` | Set to `true` behind HTTPS |
| `SOPHON_LLM_BASE_URL` | OpenAI-compatible endpoint |
| `SOPHON_LLM_API_KEY` | LLM API key |
| `SOPHON_LLM_MODEL` | LLM model name |
| `SOPHON_EMBEDDING_BASE_URL` | Embedding endpoint |
| `SOPHON_EMBEDDING_API_KEY` | Embedding API key |
| `SOPHON_HITL_ENABLED` | Enable human approval |

See [`config.example.yml`](./config.example.yml) for the complete template.

## First Login

- The default username is controlled by `auth.bootstrap_admin.username` or `SOPHON_ADMIN_USERNAME`.
- The initial password comes from `auth.bootstrap_admin.password`, `SOPHON_ADMIN_PASSWORD`, or the generated password file.
- The generated password file is `bootstrap_admin_password.txt` under the data directory.
- Change the password immediately after the first login and remove the generated password file.

## Security and Audit

- Use HTTPS in production and set `SOPHON_COOKIE_SECURE=true`.
- Deploy behind a trusted network or an authenticated reverse proxy.
- Review MCP servers, custom tools, and high-risk commands before enabling them.
- Treat workspaces, attachments, tool output, and vulnerability evidence as sensitive data.
- Rotate LLM, Embedding, and third-party credentials regularly.
- Back up the SQLite database, `config.yml`, workspaces, attachments, roles, and skills.

Sophon does not guarantee complete vulnerability coverage. Model output must be reviewed by qualified security personnel before being used as a finding or remediation decision.

## Security Statement

Sophon may only be used against systems owned, operated, or controlled by the user's organization, or for security testing, code review, and defensive exercises performed with explicit written authorization from the target owner.

Users must confirm the authorization authority, target scope, time window, permitted techniques, data handling rules, and emergency contacts before testing. Any access, scanning, exploitation, disruption, collection, or retention beyond the written authorization is prohibited.

To the maximum extent permitted by law, the project authors, contributors, and maintainers disclaim all liability for misuse, unauthorized testing, illegal activity, configuration errors, tool defects, model output, data disclosure, business interruption, property damage, or third-party claims.

This statement is not legal advice and does not replace a formal authorization document or professional legal guidance.

## License

This repository does not include a project-level `LICENSE` file. All rights are reserved unless the copyright owner grants written permission. Third-party tools and dependencies remain under their respective licenses.

</details>
