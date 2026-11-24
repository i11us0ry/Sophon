---
name: java-code-audit
description: >-
  Sophon Java Web 源码审计总控。用于在完成快速匹配、路由与参数梳理、鉴权审计、组件漏洞、调用链追踪、SQL/XXE/上传/文件读取/反序列化/SSRF/表达式注入检测、利用链分析和报告交付
metadata:
  tags: [代码审计, java, 源码审计, 安全审计]
---

# Sophon Java 代码审计总控

本技能是 Java Web 审计的方法入口，可按当前项目事实和证据缺口选择路由、鉴权、依赖、调用链或专项方法。

## 适用场景

适合从 Java Web 项目源码或二进制目录开始，建立项目结构、路由、鉴权、依赖、调用链和漏洞证据。

## 不适用场景

如果只是解释代码、查看单个依赖或验证一条已知入口，可直接使用对应 Skill，不必启动全量审计。

## 核心判断

先根据项目结构和证据缺口选择审计范围，再决定是否进入路由、追踪、专项检测或利用链阶段。快速匹配和组件扫描只提供候选，不提供漏洞结论。

## 证据标准

- 每条漏洞结论必须有文件、类、方法、参数流和 Sink 证据。
- 路由与鉴权结果需要与具体入口对应。
- 组件 CVE 需要结合实际版本、使用位置和可达入口。
- 仅有模式命中、版本命中或反编译字符串时不得确认漏洞。

## 决策树

- 项目材料可用：识别框架、模块和危险面。
- 路由和鉴权缺失：补充 route/auth 审计。
- 候选 Sink 明确：进入调用链追踪。
- 参数可控性不足：继续证明来源和净化点。
- 证据闭合：进入专项结论和报告；否则降级或停止。

## 常见误判

- 把快速匹配命中当成漏洞。
- 把框架识别当成攻击面完整。
- 只读 Controller，不追踪 Service/DAO。
- 把 class 反编译字符串当作运行时证据。
- 仅有组件版本命中就认定漏洞成立。

## 适用范围

适用于：

- Spring MVC、Spring Boot、Servlet、JAX-RS、Struts 2、CXF Web Service 等 Java Web 项目。
- Maven、Gradle、JAR、WAR、解包后的 class、反编译源码和源码目录。
- 全量审计、快速审计、指定路由审计、增量审计和指定漏洞类型审计。
- SQL 注入、XXE、文件上传、文件读取、反序列化、SSRF、表达式注入、鉴权绕过和组件漏洞。

## 工具参考

- 将上游中的 `/java-audit-pipeline`、`/java-route-mapper`、`/java-route-tracer` 等调用理解为调用 `read_skill` 加载同名技能并执行其步骤。
- 不需要照搬上游命令行入口。读取本技能后直接按阶段执行。

## 分析视角

### 快速匹配

1. 从当前项目工作区、会话附件、项目事实和已解包目录中自动定位源码与二进制，不要求用户重复提供路径。
2. 识别项目类型、模块、构建文件、源码目录和二进制目录。
3. 在本地执行快速危险模式扫描，重点检查：
   - `Runtime.exec`、`ProcessBuilder`、JNDI lookup。
   - `ObjectInputStream`、Fastjson、Jackson、XStream、Hessian、SnakeYAML。
   - `Statement.execute`、SQL 拼接、MyBatis `${}`、HQL 拼接。
   - XML 解析器、文件上传、文件读取、HTTP 客户端和表达式引擎。
4. 将原始命中写为项目审计候选或 `project_record_audit(action=cell)`，标记为模式命中，不得直接提升为已确认漏洞。

### 路由、鉴权与组件信息

按需加载并执行：

- `java-route-mapper`：提取全部 HTTP 路由、参数、请求方法、Content-Type 和入口方法。
- `java-auth-audit`：识别 Shiro、Spring Security、JWT、Filter、Interceptor、注解鉴权和自定义鉴权。
- `java-vuln-scanner`：优先使用 `java-vuln-scanner/references/java-vulnerability.yaml` 本地规则扫描依赖。OSV.dev 在线查询只在 `network_allowed=yes` 时使用。

路由、鉴权和组件结果写回项目审计台账；有证据的漏洞使用 `project_report_finding`，不要求生成固定目录骨架。

### 交叉分级

将路由、鉴权和组件结果合并：

- `P0`：无鉴权或明确公开的高风险入口。
- `P1`：鉴权可能被绕过、权限模型不清或高风险业务入口。
- `P2`：需要已认证或低风险入口。

组件 CVE 必须结合项目实际依赖版本、调用范围和公开入口评估，不能只凭版本号直接写成可利用漏洞。

### 调用链追踪

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

### 专项漏洞检测

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

### 利用链与复核

1. 汇总专项发现，按文件、Sink 和参数去重。
2. 检查鉴权状态、参数可控性和安全过滤。
3. 将多步组合标记为候选利用链，不把静态推断写成实际利用结果。
4. 对高风险结论执行二次复核：
   - 证据是否来自项目文件。
   - 行号和符号是否存在。
   - 参数是否能从入口到达 Sink。
   - 是否遗漏框架默认鉴权、全局 Filter 或参数校验。
5. 证据不足时降级为 `NEEDS_VALIDATION` 或 `PATTERN`。

### 报告

报告内容通过项目报告和漏洞工具写回，不强制生成固定文件名或目录。

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

## 结果参考

- 可记录代码位置、参数流、证据状态和修复方向。
- 密钥、Token 和凭据可只保留类型、位置和脱敏证据。

共享约束和评级规范见：

- `../java-shared/SOPHON_RUNTIME.md`
- `../java-shared/OUTPUT_STANDARD.md`
- `../java-shared/SEVERITY_RATING.md`
- `../java-shared/DECOMPILE_STRATEGY.md`
