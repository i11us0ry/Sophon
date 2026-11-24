---
name: java-vuln-scanner
metadata:
  tags: [java, 依赖审计, sca, cve]
description: Java 组件版本漏洞检测工具。扫描 pom.xml、build.gradle 或 jar 文件中的第三方依赖，匹配已知漏洞规则（CVE）并生成漏洞检测报告。适用于：(1) Java 项目依赖安全审计，(2) 识别 Log4j、Fastjson、Shiro、Spring 等高危组件漏洞，(3) jar 包反编译后的依赖提取。支持按目录层级分组输出，支持通过 CFR 反编译 .class/.jar 文件提取依赖信息。
---

# Java 组件漏洞扫描器

扫描 Java 项目依赖中的已知漏洞，支持 130+ 条 CVE 规则，按模块分组输出，并由 AI 生成漏洞触发点检查结果。

## 适用场景

适合已知 Java 项目依赖、JAR/WAR 或构建文件，需要匹配组件版本漏洞并判断当前项目是否真正使用到相关组件和入口。

## 不适用场景

只有组件版本命中、没有实际使用位置或入口证据时，不应直接生成可利用漏洞。联网查询是否可用由运行时决定。

## 核心判断

扫描结果回答“依赖是否命中已知漏洞规则”，漏洞结论还要回答“该组件是否被项目使用、相关功能是否可达、攻击前置条件是否满足”。

## 证据标准

- 依赖命中需要提供模块、组件、版本、CVE 和规则依据。
- 可利用判断需要额外提供使用位置、入口、配置或调用证据。
- 版本无法准确提取时标记不确定，不猜测。
- 扫描结果、在线数据库结果和 AI 推断必须分层。

## 决策树

- 依赖版本明确且规则命中：检查组件是否实际存在和使用。
- 组件未使用或不可达：降低结论等级。
- 组件可达且存在受影响入口：进入专项验证或标记待验证。
- 版本不确定：先反编译或读取元数据。
- 无命中：记录扫描范围和规则版本，不宣称绝对安全。

## 常见误判

- 把传递依赖版本当成实际加载版本。
- 把 version range 命中当成可利用。
- 把 CVE 描述直接写成当前项目影响。
- 忽略容器自带组件或 shaded/fat jar。
- 把扫描器“无命中”当成不存在漏洞。

## 工作流程

### 1. 确定扫描目标

支持的输入类型：
- `pom.xml` - Maven 项目
- `build.gradle` - Gradle 项目
- `.jar` 文件 - 从文件名或 META-INF 提取依赖信息
- 目录 - 递归扫描上述所有文件，自动按模块分组

### 2. 处理 jar/class 文件（需要反编译时）

当目标是 `.jar` 或 `.class` 文件且无法直接提取依赖信息时，可优先从 JAR 文件名、`META-INF/MANIFEST.MF`、`META-INF/maven/**/pom.properties` 和包元数据提取。元数据不足时，再按当前环境可用的能力选择反编译工具或字节码检索方式。

### 3. 执行漏洞扫描

如当前环境已有依赖扫描脚本或规则库，可选择使用；没有时也可直接从构建文件和包元数据提取组件信息。

```bash
python3 scripts/scan_dependencies.py <目标路径> \
  --rules references/java-vulnerability.yaml \
  --no-deps
```

参数说明：
- `<目标路径>`: pom.xml、build.gradle、jar 文件或目录
- `--rules/-r`: 漏洞规则文件路径（使用内置规则）
- `--format/-f`: 输出格式 (markdown/json)
- `--output/-o`: 指定输出路径（不指定则自动生成）
- `--depth/-d`: 模块分组深度（默认: 2）
- `--no-deps`: 不显示依赖列表（简化输出）
- `--no-save`: 仅输出到终端，不保存文件

### 4. 检查扫描结果

报告按模块分组，每个模块按严重级别分类：
- 🔴 **Critical**: 立即修复（Log4Shell、Fastjson RCE、Shiro 反序列化等）
- 🟠 **High**: 尽快修复（Spring Boot Actuator、XStream 等）
- 🟡 **Medium**: 计划修复（JDBC 驱动漏洞、Guava 等）
- 🔵 **Low**: 建议升级（过时组件）

### 5. AI 漏洞触发点分析（重要）

扫描完成后，应基于扫描结果，按照 `references/OUTPUT_TEMPLATE.md` 模板填充完整报告（**单个文件**）。

#### 分析步骤

1. 读取 Python 脚本生成的扫描结果
2. **识别项目运行环境**：
   - 检查项目使用的框架：Spring MVC / Spring Boot / Struts2 / Servlet / JAX-RS 等
   - 检查容器类型：Tomcat / Jetty / Undertow / WebLogic / WildFly 等
   - 查找配置文件：`web.xml`、`struts.xml`、`application.yml`、`applicationContext.xml` 等
3. **提取路由和入口点**：
   - 扫描 Controller / Action / Servlet 类，提取 HTTP 路由映射
   - 识别文件上传、JSON/XML 解析、用户输入处理等关键入口
   - 结合 java-route-mapper 技能（如已加载）获取完整路由信息
4. 提取检测到的**唯一漏洞组件**列表（去重）
5. 对每个候选漏洞，继续判断触发条件、危险代码模式、攻击向量、受影响入口和修复方向。

#### 环境识别方法

根据以下特征识别项目环境（参考 java-route-mapper 技能的识别策略）：

**Web 框架识别：**

| 框架 | 识别特征 | 配置文件 | 关键依赖 |
|------|---------|---------|---------|
| Spring MVC | `@Controller`、`@RequestMapping`、`@RestController` | `dispatcher-servlet.xml`、`spring-mvc.xml` | `spring-webmvc.jar` |
| Spring Boot | `@SpringBootApplication`、Spring Boot starter | `application.properties`、`application.yml` | `spring-boot-starter-*.jar` |
| Struts 2 | `ActionSupport`、`\<action\>` 配置 | `struts.xml`、`struts-plugin.xml` | `struts2-core.jar` |
| Servlet | `HttpServlet`、`@WebServlet`、`\<servlet\>` 配置 | `web.xml` | `javax.servlet-api.jar` |
| JAX-RS | `@Path`、`@GET`、`@POST`、`@PathParam` | `web.xml`（REST servlet 映射） | `jersey-*.jar`、`cxf-rt-*.jar` |
| CXF Web Services | `@WebService`、`\<jaxws:endpoint\>` | `applicationContext.xml`、`cxf-servlet.xml` | `cxf-*.jar` |

**容器识别：**

| 容器 | 识别特征 | 配置文件 |
|------|---------|---------|
| Tomcat | `catalina.jar`、`org.apache.catalina` | `server.xml`、`context.xml` |
| Jetty | `jetty-*.jar`、`org.eclipse.jetty` | `jetty.xml`、`webdefault.xml` |
| Undertow | `undertow-*.jar`、`io.undertow` | `undertow-handlers.conf` |
| WebLogic | `weblogic.jar`、`weblogic.xml` | `weblogic.xml`、`weblogic-application.xml` |
| WildFly/JBoss | `jboss-*.jar`、`org.jboss` | `jboss-web.xml`、`standalone.xml` |

**框架组合识别：**

多框架混合项目需要分别识别并检查：
- Struts2 + Spring：检查 `struts-spring-plugin.jar` 和 Spring 配置
- Spring MVC + CXF：检查 `\<jaxws:endpoint\>` 和 `@Controller` 共存
- Servlet + Filter 链：检查 `web.xml` 中的 filter-mapping 顺序

## 漏洞规则覆盖

规则文件 `references/java-vulnerability.yaml` 包含 130+ 条规则，覆盖：

| 组件类别 | 主要漏洞 |
|---------|---------|
| Log4j | CVE-2021-44228 (Log4Shell), CVE-2021-45046 |
| Fastjson | CVE-2022-25845, CVE-2017-18349 |
| Spring | CVE-2022-22965 (Spring4Shell), CVE-2022-22963 |
| Struts2 | S2-045, S2-046, S2-057, S2-061 |
| Shiro | CVE-2016-4437, CVE-2020-11989, CVE-2020-17510 |
| Jackson | CVE-2020-36518, CVE-2019-12384 |
| XStream | CVE-2021-39144 等 15 个 CVE |
| ActiveMQ | CVE-2023-46604 |
| JDBC 驱动 | MySQL, PostgreSQL, H2, Derby 等 |

## 示例

### 完整扫描流程

```bash
# 1. 执行扫描
python3 scripts/scan_dependencies.py /path/to/webapp \
  --rules references/java-vulnerability.yaml \
  --no-deps

# 2. 输出示例:
# [INFO] 创建输出目录: webapp_audit/vuln_report
# [INFO] 报告已保存到: webapp_audit/vuln_report/webapp_vuln_report_20260204_101747.md
# 📊 扫描摘要:
#    模块数量: 4
#    依赖总数: 262
#    漏洞总数: 80
#    🔴 严重: 24

# 3. AI 自动读取报告并追加触发点检查结果
```

扫描结果可选择写回项目事实、审计单元或漏洞记录；本技能不规定固定文件、章节或命名。
