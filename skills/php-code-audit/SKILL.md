---
name: php-code-audit
description: >-
  Sophon PHP Web 源码审计总控。用于在授权范围内完成路由与参数建模、鉴权映射、依赖检查、Sink 兜底、数据流追踪、分类漏洞审计、利用链聚合和证据化报告。
metadata:
  tags: [代码审计, php, 源码审计, 安全审计]
---

# Sophon PHP 代码审计总控

本技能是 Sophon 的 PHP Web 审计入口。完整方法保留在 `php-audit-pipeline`，路由、追踪、鉴权和漏洞专项规则位于对应 `php-*` 技能。

## 适用范围

适用于：

- Laravel、Symfony、Yii2、ThinkPHP、WordPress、CodeIgniter、Slim 和原生 PHP Web 项目。
- Composer 项目、传统 PHP 站点、MVC 项目、插件/主题代码和多模块仓库。
- SQL、NoSQL、命令、表达式、LDAP、XXE、模板、CRLF、开放重定向等注入类风险。
- 文件读取、上传、写入、解压、文件系统和路径穿越风险。
- 鉴权、越权、会话、Cookie、CSRF、配置、加密、业务逻辑和日志审计。
- 跨漏洞利用链聚合和质量报告。

不适用于：

- 未授权的远程探测、真实请求、漏洞利用或凭据使用。
- 执行项目 PHP 代码、Composer 脚本、测试、shell、Dockerfile 或未知脚本。
- 自动安装 PHP、Composer 或扩展依赖。

## 上游缺失项

上游 README 和流水线提到以下技能，但源项目没有对应目录：

- `php-ssrf-audit`
- `php-xss-audit`
- `php-csrf-audit`

禁止假装加载或执行这些技能。覆盖矩阵必须写为“已延期：上游技能缺失”，并在待补证池保留相关 Sink 和静态证据。

## 输入

| 变量 | 必填 | 说明 |
|---|---|---|
| `source_path` | 是 | PHP 项目源码根目录 |
| `output_path` | 否 | 工作区内的输出目录，默认 `{source_path}_audit` |
| `audit_mode` | 否 | `standard`、`quick`、`incremental` 或 `targeted` |
| `audit_scope` | 否 | 模块、插件、主题、路由或漏洞类型范围 |
| `authorized_only` | 是 | 即使只做静态文件审计也必须确认授权 |
| `network_allowed` | 否 | 默认 `no`；不用于普通静态审计 |

缺少源码路径或授权范围时，只返回最小补充输入，不猜测项目内容。

## 路径映射

上游技能中的 `shared/...` 在 Sophon 中映射到：

```text
../php-shared/...
```

例如：

- `shared/SEVERITY_RATING.md` -> `../php-shared/SEVERITY_RATING.md`
- `shared/EVIDENCE_POINT_IDS.md` -> `../php-shared/EVIDENCE_POINT_IDS.md`
- `shared/PHP_SINK_REFERENCE.md` -> `../php-shared/PHP_SINK_REFERENCE.md`
- `shared/IO_PATH_CONVENTION.md` -> `../php-shared/IO_PATH_CONVENTION.md`

## Sophon 工具映射

- 将上游的 `php-route-mapper`、`php-route-tracer`、`php-*-audit` 调用理解为使用 `read_skill` 加载同名技能并执行。
- 忽略 Cursor、Claude Code、Agent Teams 和专用命令入口。
- 需要分拆时使用 `pent_agent_execute`，静态审计只允许 `mode=read_only` 或 `mode=read_write`。
- 禁止 `mode=execute` 和 `mode=diagnose`。
- 并发能力不足时串行执行，禁止声称未运行的技能已经完成。

## 执行流程

### 阶段 1：路由、参数与鉴权

1. 加载 `php-route-mapper`，枚举全部 HTTP 路由、CLI、Cron、队列、Hook 和 Include 入口。
2. 为每条路由记录 HTTP 方法、路径、处理函数、文件位置、参数来源、类型和请求模板。
3. 加载 `php-auth-audit` 的 `STATIC_MAPPING` 模式，生成路由鉴权映射和 P0/P1 分桶。
4. 加载 `php-vuln-scanner`，只基于本地 `composer.json`、`composer.lock` 和已有规则做静态匹配。
5. 仅在检测到对应框架时加载 Laravel、Symfony、Yii、ThinkPHP、WordPress 或 CodeIgniter 专项技能。

输出建议：

```text
{output_path}/route_mapping/
{output_path}/auth_audit/
{output_path}/vuln_report/
{output_path}/framework_audit/
```

### 阶段 2：Sink 兜底与高危入口

在完整路由之外，扫描业务 PHP 文件的危险 Sink：

- 命令：`exec/system/shell_exec/passthru/proc_open/popen/pcntl_exec` 和反引号。
- 代码执行：`eval/assert`、旧版 `preg_replace /e`。
- 反序列化：`unserialize`、Phar、对象注入入口。
- SQL/NoSQL：`query/exec/prepare`、ORM 原生查询、MongoDB filter。
- SSRF：`curl_exec`、`file_get_contents($url)`、`fsockopen`、`get_headers`。
- 文件：`include/require`、读取、写入、上传、解压、删除、重命名。
- 输出与重定向：`header`、`setcookie`、模板渲染、`Location`。

所有无路由或无法证明可达性的命中必须使用稳定合成 ID，例如：

```text
SINK_ONLY:{序号}:{文件基名}:{行号}
ENTRY_CLI:{脚本标识}
ENTRY_CRON:{任务名}
ENTRY_QUEUE:{消费者标识}
ENTRY_HOOK:{hook 名}
ENTRY_INCLUDE:{文件}:{符号}
```

### 阶段 3：数据流追踪

加载 `php-route-tracer`，从处理函数、CLI、Hook 或合成入口追踪到 Sink：

```text
入口 -> 参数读取 -> 分支/校验 -> 变量传递 -> Sink
```

每个 trace 必须包含：

- 参数可控性矩阵。
- Sink 定位。
- Sink Summary。
- Trace 完整性声明。
- Sink Evidence Type Checklist。
- `EVID_*` 证据点。

### 阶段 4：专项漏洞审计

只加载与 trace 结果匹配的技能：

| Sink 或风险 | 技能 |
|---|---|
| SQL | `php-sql-audit` |
| NoSQL | `php-nosql-audit` |
| 命令 | `php-cmd-audit` |
| 表达式 | `php-expr-audit` |
| LDAP | `php-ldap-audit` |
| XML 外部实体 | `php-xxe-audit` |
| 文件读取/包含 | `php-file-read-audit` |
| 文件上传 | `php-file-upload-audit` |
| 文件写入 | `php-file-write-audit` |
| 文件系统操作 | `php-filesystem-audit` |
| 归档解压 | `php-archive-extract-audit` |
| 反序列化 | `php-deser-audit` |
| 模板注入 | `php-tpl-audit` |
| 开放重定向 | `php-open-redirect-audit` |
| CRLF | `php-crlf-audit` |
| 鉴权/越权 | `php-auth-audit` |
| 会话/Cookie/JWT | `php-session-cookie-audit` |
| 配置 | `php-config-audit` |
| 加密 | `php-crypto-audit` |
| 业务逻辑 | `php-logic-audit` |
| 安全日志 | `php-logging-audit` |

SSRF、XSS、CSRF 必须进入待补证池，不得由其他技能冒充对应专项技能。

### 阶段 5：利用链复核

加载 `php-exploit-chain-audit`：

- 只消费已有漏洞证据。
- 使用链路最弱环节确定整体状态。
- 缺少鉴权、参数可控性、文件落点或执行条件时，链路只能是待验证。
- 不补造新的 `EVID_*` 证据点。

### 阶段 6：质量报告

输出至少包含：

```text
{output_path}/{project_name}_代码审计_{timestamp}.md
{output_path}/PARTIAL_RESULTS.md  # 仅中断或未完成时
```

最终报告必须包含：

- 子技能覆盖矩阵，每项必须为已执行、不适用或已延期，并写依据。
- 风险统计、漏洞详情、修复建议和框架专项汇总。
- 路由、鉴权、Sink、分支和证据点覆盖率。
- “Trace 未闭合 / 待补证风险池”。
- 上游缺失的 SSRF、XSS、CSRF 专项说明。
- 已检查但未发现问题的范围。

## 状态与证据

- `CONFIRMED`：静态证据链完整，入口、参数流、分支和 Sink 可复核。
- `NEEDS_VALIDATION`：存在强线索但条件未闭合。
- `ENV_DEPENDENT`：依赖特定 PHP 配置、扩展、Web 服务器或部署条件。
- `NOT_EXPLOITABLE`：有有效防护或 Sink 实际不可执行。
- `PATTERN`：仅命中危险模式。

严重度与证据状态必须分开填写。没有 trace 或 `EVID_*` 闭合时，不得把模式命中写成已确认漏洞。

## 安全约束

1. 只读用户授权的本地源码，不修改原始项目。
2. 不启动 PHP 服务、不执行项目代码、不运行 Composer 脚本或测试。
3. 不访问真实 URL、内网地址、云元数据服务或第三方 API。
4. 不执行 `composer audit`；需要联网 advisory 数据时必须由用户明确授权，并避免自动安装。
5. 报告中的 HTTP 请求和 PoC 仅是静态模板，不在审计过程中发送。
6. 密钥、Token、Cookie 和数据库凭据只记录脱敏位置，不使用其访问服务。
7. 中间文件和报告只写当前会话工作区，禁止写系统目录或全局临时目录。

执行策略和输出标准见：

- `../php-shared/PHP_AUDIT_EXECUTION_POLICY.md`
- `../php-shared/PHP_AUDIT_UNIFIED_STANDARD.md`
- `../php-shared/EVIDENCE_POINT_IDS.md`
- `../php-shared/IO_PATH_CONVENTION.md`
- `../php-shared/PHP_SINK_REFERENCE.md`
- `../php-shared/SEVERITY_RATING.md`
