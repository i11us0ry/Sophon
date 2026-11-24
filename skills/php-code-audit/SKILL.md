---
name: php-code-audit
description: >-
  Sophon PHP Web 源码审计总控。用于在完成路由与参数建模、鉴权映射、依赖检查、Sink 兜底、数据流追踪、分类漏洞审计、利用链聚合和证据化报告
metadata:
  tags: [代码审计, php, 源码审计, 安全审计]
---

# Sophon PHP 代码审计总控

本技能是 Sophon 的 PHP Web 审计入口。完整方法保留在 `php-audit-pipeline`，路由、追踪、鉴权和漏洞专项规则位于对应 `php-*` 技能。

## 适用场景

适合从项目入口开始，建立 PHP Web 的源码范围、路由、参数、鉴权、数据流、Sink 和漏洞证据全貌。

## 不适用场景

如果用户只要求查询单个函数、解释单个文件或确认单个已知漏洞，不必默认启动完整六阶段审计。

## 核心判断

先建立项目结构和可达入口，再根据证据缺口选择路由映射、数据流追踪、专项审计或利用链复核。阶段编号是组织方式，不是强制执行顺序。

## 证据标准

- 每条结论必须绑定源码位置和关键代码片段。
- 参数可控性、分支执行和 Sink 落点需要独立证据。
- 仅扫描到危险函数不得升级为漏洞。
- 输出必须区分已确认、待验证、环境依赖和不可利用。

## 决策树

- 源码结构未知：先识别框架、入口、模块和依赖。
- 路由未知：加载 `php-route-mapper`。
- 数据流不闭合：加载 `php-route-tracer`。
- Sink 明确：选择对应 `php-*-audit`。
- 多条漏洞存在共同前置条件：再进入 `php-exploit-chain-audit`。
- 证据不足：保留候选，不强行完成全部阶段。

## 常见误判

- 把所有项目都按同一种 PHP 框架处理。
- 只看 Sink 名称，不看参数来源和分支。
- 把覆盖矩阵完成度当成漏洞结论质量。
- 把 vendor 代码和业务代码混为同一风险面。
- 在没有入口证据时直接做漏洞利用链。

## 适用范围

适用于：

- Laravel、Symfony、Yii2、ThinkPHP、WordPress、CodeIgniter、Slim 和原生 PHP Web 项目。
- Composer 项目、传统 PHP 站点、MVC 项目、插件/主题代码和多模块仓库。
- SQL、NoSQL、命令、表达式、LDAP、XXE、模板、CRLF、开放重定向等注入类风险。
- 文件读取、上传、写入、解压、文件系统和路径穿越风险。
- 鉴权、越权、会话、Cookie、CSRF、配置、加密、业务逻辑和日志审计。
- 跨漏洞利用链聚合和质量报告。

## 工具参考

- 将上游的 `php-route-mapper`、`php-route-tracer`、`php-*-audit` 调用理解为使用 `read_skill` 加载同名技能并执行。
## 分析视角

### 路由、参数与鉴权

1. 加载 `php-route-mapper`，枚举全部 HTTP 路由、CLI、Cron、队列、Hook 和 Include 入口。
2. 为每条路由记录 HTTP 方法、路径、处理函数、文件位置、参数来源、类型和请求模板。
3. 加载 `php-auth-audit` 的 `STATIC_MAPPING` 模式，生成路由鉴权映射和 P0/P1 分桶。
4. 加载 `php-vuln-scanner`，只基于本地 `composer.json`、`composer.lock` 和已有规则做静态匹配。
5. 仅在检测到对应框架时加载 Laravel、Symfony、Yii、ThinkPHP、WordPress 或 CodeIgniter 专项技能。

路由、鉴权和组件结果写回项目审计台账；漏洞使用 `project_report_finding`，不强制固定输出目录。

### Sink 兜底与高危入口

在完整路由之外，扫描业务 PHP 文件的危险 Sink：

- 命令：`exec/system/shell_exec/passthru/proc_open/popen/pcntl_exec` 和反引号。
- 代码执行：`eval/assert`、旧版 `preg_replace /e`。
- 反序列化：`unserialize`、Phar、对象注入入口。
- SQL/NoSQL：`query/exec/prepare`、ORM 原生查询、MongoDB filter。
- SSRF：`curl_exec`、`file_get_contents($url)`、`fsockopen`、`get_headers`。
- 文件：`include/require`、读取、写入、上传、解压、删除、重命名。
- 输出与重定向：`header`、`setcookie`、模板渲染、`Location`。

无路由或无法证明可达性的命中可以使用稳定的描述性标识，例如：

```text
SINK_ONLY:{序号}:{文件基名}:{行号}
ENTRY_CLI:{脚本标识}
ENTRY_CRON:{任务名}
ENTRY_QUEUE:{消费者标识}
ENTRY_HOOK:{hook 名}
ENTRY_INCLUDE:{文件}:{符号}
```

### 数据流追踪

加载 `php-route-tracer`，从处理函数、CLI、Hook 或合成入口追踪到 Sink：

```text
入口 -> 参数读取 -> 分支/校验 -> 变量传递 -> Sink
```

可记录以下数据流信息：

- 参数可控性矩阵。
- Sink 定位。
- Sink Summary。
- Trace 完整性声明。
- Sink Evidence Type Checklist。
- `EVID_*` 证据点。

### 专项漏洞审计

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

SSRF、XSS、CSRF 可保留在待补证范围。

### 利用链复核

加载 `php-exploit-chain-audit`：

- 只消费已有漏洞证据。
- 使用链路最弱环节确定整体状态。
- 缺少鉴权、参数可控性、文件落点或执行条件时，链路只能是待验证。

### 阶段 6：质量报告

输出至少包含：

```text
```

最终报告必须包含：

- 子技能覆盖矩阵，每项必须为已执行、不适用或已延期，并写依据。
- 风险统计、漏洞详情、修复建议和框架专项汇总。
- 路由、鉴权、Sink、分支和证据点覆盖率。
- “Trace 未闭合 / 待补证风险池”。
- 上游缺失的 SSRF、XSS、CSRF 专项说明。
- 已检查但未发现问题的范围。

## 证据标准与状态

- `CONFIRMED`：静态证据链完整，入口、参数流、分支和 Sink 可复核。
- `NEEDS_VALIDATION`：存在强线索但条件未闭合。
- `ENV_DEPENDENT`：依赖特定 PHP 配置、扩展、Web 服务器或部署条件。
- `NOT_EXPLOITABLE`：有有效防护或 Sink 实际不可执行。
- `PATTERN`：仅命中危险模式。

严重度与证据状态必须分开填写。没有 trace 或 `EVID_*` 闭合时，不得把模式命中写成已确认漏洞。

## 安全约束

2. 不启动 PHP 服务、不执行项目代码、不运行 Composer 脚本或测试。
4. 不执行 `composer audit`；需要联网 advisory 数据时必须由用户明确授权，并避免自动安装。
5. 报告中的 HTTP 请求和 PoC 仅是静态模板，不在审计过程中发送。
6. 密钥、Token、Cookie 和数据库凭据只记录脱敏位置，不使用其访问服务。

执行策略和输出标准见：

- `../php-shared/PHP_AUDIT_EXECUTION_POLICY.md`
- `../php-shared/PHP_AUDIT_UNIFIED_STANDARD.md`
- `../php-shared/EVIDENCE_POINT_IDS.md`
- `../php-shared/IO_PATH_CONVENTION.md`
- `../php-shared/PHP_SINK_REFERENCE.md`
- `../php-shared/SEVERITY_RATING.md`
