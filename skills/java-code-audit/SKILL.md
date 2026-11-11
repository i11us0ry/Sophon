---
name: java-code-audit
description: >-
  Sophon Java Web 源码审计总控。用于在授权范围内完成快速匹配、路由与参数梳理、鉴权审计、组件漏洞、调用链追踪、SQL/XXE/上传/文件读取/反序列化/SSRF/表达式注入检测、利用链分析和报告交付。
metadata:
  tags: [代码审计, java, 源码审计, 安全审计]
---

# Sophon Java 代码审计总控

本技能是 Sophon 中的 Java Web 审计入口。完整上游流水线保存在 `java-audit-pipeline`，专项检测规范分别位于对应 `java-*` 技能。本文件负责输入确认、阶段路由、工具映射、证据门控和最终交付。

## 适用范围

适用于：

- Spring MVC、Spring Boot、Servlet、JAX-RS、Struts 2、CXF Web Service 等 Java Web 项目。
- Maven、Gradle、JAR、WAR、解包后的 class、反编译源码和源码目录。
- 全量审计、快速审计、指定路由审计、增量审计和指定漏洞类型审计。
- SQL 注入、XXE、文件上传、文件读取、反序列化、SSRF、表达式注入、鉴权绕过和组件漏洞。

不适用于：

- 未授权的远程目标探测、漏洞利用或真实业务请求。
- 自动安装 JDK、CFR、Python 包或其他依赖。
- 执行来源不明的 `jar`、`class`、shell 或项目内脚本。

## 输入

开始时确认并继承以下变量：

| 变量 | 必填 | 说明 |
|---|---|---|
| `source_path` | 是 | Java 项目源码、解包目录或二进制分析目录 |
| `output_path` | 否 | 输出目录，必须位于当前会话工作区；默认 `{source_path}_audit` |
| `audit_mode` | 否 | `standard`、`quick`、`incremental` 或 `targeted` |
| `audit_scope` | 否 | 模块、包、路由或漏洞类型范围 |
| `authorized_only` | 是 | 静态文件审计也必须确认授权 |
| `network_allowed` | 否 | 默认 `no`；OSV.dev 在线查询必须由用户明确授权 |

缺少 `source_path` 或授权范围时，只返回最小补充输入，不猜测项目内容。

## Sophon 工具映射

- 将上游中的 `/java-audit-pipeline`、`/java-route-mapper`、`/java-route-tracer` 等调用理解为调用 `read_skill` 加载同名技能并执行其步骤。
- 将上游的 Agent Teams、TaskCreate、SendMessage 生命周期描述视为上游实现细节；Sophon 中使用 `pent_agent_execute`。
- 静态并行分析只允许 `mode=read_only` 或 `mode=read_write`，禁止 `mode=execute` 和 `mode=diagnose`。
- `subagent_max_concurrency` 以 Sophon 配置为准；无法并行时由主 Agent 串行执行，不得伪造并发或完成状态。
- JAR、WAR 或 CLASS 需要反编译时优先调用 `java_decompile`；输出必须写入当前会话工作区，随后只读取相关类和包，不把完整反编译结果放入上下文。
- 不需要照搬上游命令行入口。读取本技能后直接按阶段执行。

## 阶段流程

### 阶段 0：输入与快速匹配

1. 核对 `source_path`、输出路径和授权范围。
2. 识别项目类型、模块、构建文件、源码目录和二进制目录。
3. 在本地执行快速危险模式扫描，重点检查：
   - `Runtime.exec`、`ProcessBuilder`、JNDI lookup。
   - `ObjectInputStream`、Fastjson、Jackson、XStream、Hessian、SnakeYAML。
   - `Statement.execute`、SQL 拼接、MyBatis `${}`、HQL 拼接。
   - XML 解析器、文件上传、文件读取、HTTP 客户端和表达式引擎。
4. 将原始命中写入 `{output_path}/quick_hits/quick_hits.md`，标记为模式命中，不得直接提升为已确认漏洞。

### 阶段 1：路由、鉴权与组件信息

按需加载并执行：

- `java-route-mapper`：提取全部 HTTP 路由、参数、请求方法、Content-Type 和入口方法。
- `java-auth-audit`：识别 Shiro、Spring Security、JWT、Filter、Interceptor、注解鉴权和自定义鉴权。
- `java-vuln-scanner`：优先使用 `java-vuln-scanner/references/java-vulnerability.yaml` 本地规则扫描依赖。OSV.dev 在线查询只在 `network_allowed=yes` 时使用。

输出建议：

```text
{output_path}/route_mapper/
{output_path}/auth_audit/
{output_path}/vuln_report/
```

### 阶段 2：交叉分级

将路由、鉴权和组件结果合并：

- `P0`：无鉴权或明确公开的高风险入口。
- `P1`：鉴权可能被绕过、权限模型不清或高风险业务入口。
- `P2`：需要已认证或低风险入口。

组件 CVE 必须结合项目实际依赖版本、调用范围和公开入口评估，不能只凭版本号直接写成可利用漏洞。

### 阶段 3：调用链追踪

使用 `java-route-tracer` 对 P0、P1 和用户指定路由追踪：

```text
HTTP 入口 -> Controller/Action -> Service -> DAO/Sink
```

每条链路至少记录：

- 入口文件、类、方法和行号。
- 参数名称、类型、来源和可控性。
- 中间方法签名、分支和过滤逻辑。
- 最终 Sink、文件位置和危险参数表达式。
- 参数是否真正可控，以及阻断条件。

### 阶段 4：专项漏洞检测

只加载与已发现 Sink 匹配的技能：

| Sink 或风险 | 技能 |
|---|---|
| SQL 拼接、MyBatis `${}`、HQL 拼接 | `java-sql-audit` |
| XML 外部实体 | `java-xxe-audit` |
| MultipartFile、FileItem、transferTo | `java-file-upload-audit` |
| FileInputStream、Files、Path | `java-file-read-audit` |
| readObject、Fastjson、JNDI、Hessian | `java-deserialization-audit` |
| HttpClient、RestTemplate、OkHttp、URLConnection | `java-ssrf-audit` |
| OGNL、SpEL、MVEL、FreeMarker、Velocity | `java-expression-inject-audit` |
| 鉴权绕过、越权、会话问题 | `java-auth-audit` |

不得为了增加报告数量启动没有对应 Sink 的专项检测。

### 阶段 5：利用链与复核

1. 汇总专项发现，按文件、Sink 和参数去重。
2. 检查鉴权状态、参数可控性和安全过滤。
3. 将多步组合标记为候选利用链，不把静态推断写成实际利用结果。
4. 对高风险结论执行二次复核：
   - 证据是否来自项目文件。
   - 行号和符号是否存在。
   - 参数是否能从入口到达 Sink。
   - 是否遗漏框架默认鉴权、全局 Filter 或参数校验。
5. 证据不足时降级为 `NEEDS_VALIDATION` 或 `PATTERN`。

### 阶段 6：报告

输出至少包含：

```text
{output_path}/quality_report.md
{output_path}/findings.json
{output_path}/PARTIAL_RESULTS.md  # 仅中断或未完成时
```

主报告必须包含：

- 审计范围、限制和工具依赖。
- 项目技术栈、模块和路由统计。
- 漏洞总表、严重度、状态和证据等级。
- 每个漏洞的位置、参数流、触发条件、影响和修复建议。
- 鉴权映射和组件漏洞摘要。
- 已测试未发现问题的覆盖说明。
- 未验证项和阻塞项。

## 漏洞状态

- `CONFIRMED`：静态证据链完整，文件、入口、参数流和 Sink 均可复核。
- `NEEDS_VALIDATION`：已有强线索，但缺少框架默认行为、部署配置或运行时条件。
- `PATTERN`：仅命中危险模式，不能证明可达和可控。
- `CLEAN`：已按范围检查，未发现对应危险路径。

严重度与证据状态必须分开填写。`PATTERN` 不能因为代码关键字高危就直接写成 Critical。

## 输出与安全约束

1. 所有中间文件和报告写入当前会话工作区，禁止写入 `/tmp` 或系统目录。
2. 源码、JAR、WAR 和报告只读或追加，不修改用户原始代码。
3. 不执行未知项目代码、构建脚本、单元测试或 shell 脚本。
4. 不自动安装依赖，不启动外部服务，不访问真实目标。
5. 本地 CFR 反编译仅在工具已存在且用户明确同意执行时使用。
6. OSV.dev、代码托管平台和其他在线查询必须明确授权。
7. 发现密钥、Token 或凭据时只记录类型、位置和脱敏证据，不使用其访问任何服务。

共享约束和评级规范见：

- `../java-shared/SOPHON_RUNTIME.md`
- `../java-shared/OUTPUT_STANDARD.md`
- `../java-shared/SEVERITY_RATING.md`
- `../java-shared/DECOMPILE_STRATEGY.md`
