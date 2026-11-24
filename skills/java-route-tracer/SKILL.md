---
name: java-route-tracer
metadata:
  tags: [代码审计, java, 调用链, 数据流, 路由]
description: Java Web 源码路由多层级调用链追踪工具。根据用户指定的路由路径，追踪从 Controller/Action 到 DAO 层的完整调用链，输出每一层的文件位置、方法签名和可传入参数。适用于多种漏洞类型的参数流向追踪：(1) SQL注入 - 追踪参数到SQL拼接点，(2) 命令注入 - 追踪参数到Runtime.exec()，(3) SSRF - 追踪参数到HTTP请求，(4) XSS - 追踪参数到响应输出，(5) 文件操作 - 追踪参数到File操作，(6) XXE/反序列化/LDAP注入/表达式注入等。支持 Spring MVC、Struts 2、Servlet、JAX-RS 等框架。**支持反编译 .class/.jar 文件提取调用链**。结合 java-route-mapper 使用可实现完整的路由+调用链审计。
---

# Java Route Tracer - 路由调用链追踪

根据用户指定的路由，追踪从入口到最终使用点的完整调用链，输出层级调用信息。**适用于多种漏洞类型的参数流向追踪。**

## 适用场景

适合已经存在明确路由、Controller/Action 或 Web Service 方法，需要追踪参数到 Service、DAO、父类和最终 Sink 的场景。

## 不适用场景

如果路由、入口或目标 Sink 尚未确定，不必先做全量追踪。仅有危险函数名称，也不能用调用链模板补写未观察到的数据流。

## 核心判断

追踪只回答数据如何流动、经过哪些分支和最终到达哪里。参数可控性、净化点、硬编码覆盖和执行点需要代码证据，漏洞结论由专项 Skill 负责。

## 证据标准

- 每层调用需要类、方法、文件、行号和关键代码片段。
- 分支需要记录可达条件、提前退出和最终路径。
- 参数可控性需要来源、转换、净化与覆盖条件对照。
- 无法闭合到 Sink 时标记部分或未闭合，不补写推断。

## 决策树

- 入口方法明确：读取签名和参数定义。
- 多方法入口：按风险和证据价值选择追踪顺序，不机械生成所有方法报告。
- 调用链中出现分支：分别记录成功路径和提前退出。
- 参数被硬编码或净化覆盖：降低可控性判定。
- 到达 Sink：交给专项审计，不自行确认漏洞。

## 常见误判

- 把同名变量当成同一参数。
- 忽略继承、接口实现、依赖注入和框架绑定。
- 只看成功分支，不看提前返回。
- 把参数出现在 SQL 字符串中直接等同于可注入。
- 把生成后的请求模板当成漏洞已成立。

## 核心功能

输出内容包括：
- **完整 HTTP 数据包** - Burp Suite 可直接使用的请求模板
- **详细参数定义** - 每个参数的名称、类型、嵌套结构
- **层级调用关系** - Controller → Service → DAO → 父类
- **参数流向追踪** - 从 HTTP 入口到最终使用点的完整路径
- **参数变量名追踪** - 同一参数在不同类中的变量名变化
- **最终使用点标注** - 参数在最终层如何被使用

## 适用漏洞类型

| 漏洞类型 | 追踪最终使用点 |
|:---------|:---------------|
| SQL 注入 | `sql + param`、`Statement.execute()`、MyBatis `${}`、Hibernate HQL 拼接 |
| 命令注入 | `Runtime.exec(cmd)`、`ProcessBuilder(cmd)` |
| SSRF | `HttpClient.execute(url)`、`URL.openConnection()`、`RestTemplate` |
| XSS | `response.getWriter().write()`、模板引擎输出、`@ResponseBody` |
| 文件操作 | `new File(path)`、`FileInputStream()`、`Files.read()` |
| XXE | `DocumentBuilder.parse()`、`SAXParser`、`XMLReader` |
| 反序列化 | `ObjectInputStream.readObject()`、`JSON.parseObject()` |
| LDAP 注入 | `DirContext.search(filter)`、`LdapTemplate` |
| 表达式注入 | `SpelExpression.getValue()`、OGNL、MVEL、Freemarker |
| 路径遍历 | `new File(basePath + userInput)`、`Paths.get()` |

---

## 工作流程

### 1. 识别追踪起点

可从路由、Controller/Action、Web Service 方法、已知 Sink 参数或源码目录开始。即使没有明确路由，也可以从危险调用点向上回溯入口。

### 2. 定位入口点与方法识别

根据框架类型定位路由入口类：

| 框架 | 入口定位方式 |
|:-----|:-------------|
| Spring MVC | `@RequestMapping` 注解匹配 |
| Struts 2 | struts.xml 中 action 配置 |
| Servlet | web.xml 或 `@WebServlet` |
| JAX-RS | `@Path` 注解匹配 |

入口类包含多个业务方法时，可按风险和证据价值选择追踪范围。

### 2.1 多方法追踪执行框架

**按风险和证据价值组织多方法追踪，可使用任务列表管理进度：**

#### 步骤 1: 统计所有方法

首先扫描入口类，识别所有需要追踪的方法，输出方法清单：

```
正在扫描入口类: UserQueryServiceImpl

发现以下 10 个方法需要追踪:
1. getBasicQuery(searchJson, pageJson, extend)
2. getAdvancedQuery(searchJson, pageJson, extend)
3. getDetailQuery(searchJson, pageJson, extend)
4. getStatisticsQuery(searchJson, pageJson, extend)
5. getExportQuery(searchJson, pageJson, extend)
... (列出所有方法)
10. getReportQuery(searchJson, pageJson, extend)

共计: 10 个方法
```

#### 步骤 2: 建立分析清单

需要时可将候选方法加入任务清单：

```python
TodoWrite([
    {"content": "追踪方法 1/10: getBasicQuery", "status": "pending", "activeForm": "追踪 getBasicQuery"},
    {"content": "追踪方法 2/10: getAdvancedQuery", "status": "pending", "activeForm": "追踪 getAdvancedQuery"},
    {"content": "追踪方法 3/10: getDetailQuery", "status": "pending", "activeForm": "追踪 getDetailQuery"},
    {"content": "追踪方法 4/10: getStatisticsQuery", "status": "pending", "activeForm": "追踪 getStatisticsQuery"},
    # ... 所有 10 个方法
    {"content": "追踪方法 10/10: getReportQuery", "status": "pending", "activeForm": "追踪 getReportQuery"},
    {"content": "生成总索引文件", "status": "pending", "activeForm": "生成总索引"}
])
```

#### 步骤 3: 逐个分析（可选组织方式）

按照 TodoList 顺序执行每个任务，根据接口数量采用不同的追踪策略：

| 接口序号 | 追踪策略 | 报告内容 |
|:---------|:---------|:---------|
| 第 1 个接口 | 完整追踪链 | 包含所有层级、分支、变量追踪、可控性判定 |
| 第 2 个及之后的接口 | 简化追踪链 | 可包含：请求模板 + 该方法参数定义 + 调用链 + Sink识别 + 可控性判定 |

**执行流程：**
1. 将当前任务标记为 `in_progress`
2. 根据接口序号选择追踪策略
3. 生成相应类型的报告文件
4. 记录当前方法进度
5. 继续下一个任务

```
--- 方法 1/10: getBasicQuery ---
状态: in_progress
[完整追踪链...]
[生成报告: myproject_trace_getBasicQuery_20260205.md]
状态: completed ✅

--- 方法 2/10: getAdvancedQuery ---
状态: in_progress
[简化追踪链...]
[生成报告: myproject_trace_getAdvancedQuery_20260205.md (简化版)]
状态: completed ✅

--- 方法 3/10: getDetailQuery ---
状态: in_progress
[简化追踪链...]
[生成报告: myproject_trace_getDetailQuery_20260205.md (简化版)]
状态: completed ✅

... 继续直到所有任务完成 ...
```

#### 步骤 4: 完成验证

所有方法追踪完成后：

1. 生成总索引文件
2. 验证生成的文件数量
3. 输出完成报告

```bash
# 验证命令
ls route_tracer/{route_name}/*.md | wc -l
# 期望结果: 11 (10个方法报告 + 1个总索引)
```

### 2.2 继续分析

如果分析中断，可从已有结果继续：

1. 检查已生成的报告文件
2. 对比方法清单，识别未完成的方法
3. 只为未完成的方法创建 TodoList 任务
4. 继续执行

```python
# 检查已完成的方法
existing_files = ls("/path/to/route_tracer/{route_name}/*.md")
completed_methods = [extract_method_name(f) for f in existing_files]

# 创建剩余任务
remaining_tasks = []
for method in all_methods:
    if method not in completed_methods:
        remaining_tasks.append({
            "content": f"追踪方法: {method}",
            "status": "pending",
            "activeForm": f"追踪 {method}"
        })

TodoWrite(remaining_tasks)
```

### 2.3 进度管理建议

| 规则 | 说明 |
|:-----|:-----|
| **建议统计** | 可先统计候选方法，帮助评估分析范围 |
| **任务清单可选** | 任务工具只用于组织多条追踪线 |
| **接口优化策略** | 当接口数量 > 3 时，采用以下优化方案：<br>- 第 1 个接口：生成完整调用链追踪（包含所有层级、分支、变量追踪）<br>- 第 2 个及之后的接口：只生成完整 Burp Suite 数据包 + 简单追踪链（不包含详细代码和分支判定） |
| **记录进度** | 有任务清单时同步状态即可 |
| **按证据停止** | 当前目标证据足够时可停止，不必为了清空任务而继续 |
| **核对覆盖** | 结束前检查已分析和未分析范围 |

### 2.4 分组组织建议

**所有接口数量统一使用以下策略，无需分批处理：**

| 接口序号 | 报告类型 | 内容 |
|:---------|:---------|:-----|
| 第 1 个 | 完整版 | 所有层级、分支、变量追踪、可控性判定（约 20000-30000 字符） |
| 第 2 个及之后 | 简化版 | 请求模板 + 该方法参数定义 + 调用链 + Sink识别 + 可控性判定（约 2000-4000 字符） |

**文件命名规范：**

| 规则 | 格式 |
|:-----|:-----|
| ✅ 正确 | `{项目名}_trace_{方法名}_{时间戳}.md` |
| ❌ 错误 | `{方法名}_{时间戳}.md` （缺少项目前缀） |

**变量替换检查：**

如果生成分析记录，确保占位变量被替换：

| 检查项 | 错误示例 | 正确示例 |
|:-------|:---------|:---------|
| 方法名 | `${method}` | `queryUserById` |
| 路由路径 | `/api/${method}` | `/biz/ws/userService` → `queryUserById` |
| 服务实现类 | `${ServiceImpl}` | `UserServiceImpl` |
| SOAP 方法标签 | `<web:${method}>` | `<web:queryUserById>` |
| 调用链方法 | `${ServiceImpl}.${method}()` | `UserServiceImpl.queryUserById()` |

**内容检查：**

- 方法名、路由和调用链中的占位内容是否已替换。
- 是否仍存在无法解释的 `${...}` 或模板变量。

### 2.5 精简记录可包含内容

| 可选内容 | 说明 |
|:---------|:-----|:---------|
| HTTP/SOAP 请求结构 | 用于说明入口和参数 |
| 请求示例 | 按证据需要生成 |
| 方法参数定义 | 从实际代码签名读取 |
| 调用链层级 | 记录入口到 Sink 的路径 |
| Sink 识别 | 标注最终使用点类型 |
| 可控性判断 | 说明参数来源和覆盖条件 |

### 2.5.1 请求示例生成建议

请求示例可使用与目标类型一致的示例值：

| Java类型 | 占位符（禁止） | 实际值生成规则 |
|:---------|:---------------|:---------------|
| String (ID类) | `{{userId}}` | 数字字符串如 `1001` |
| String (名称类) | `{{name}}` | 有意义的测试值如 `testUser` |
| String (日期类) | `{{date}}` | 标准格式如 `2026-01-01` |
| String (路径类) | `{{path}}` | 合法路径如 `/tmp/test.txt` |
| String (URL类) | `{{url}}` | 完整URL如 `http://example.com/api` |
| int/Integer | `{{count}}` | 数字如 `10` |
| boolean/Boolean | `{{flag}}` | `true` 或 `false` |
| JSON字符串 | `{{xxxJson}}` | 完整JSON如 `{"id":"1","name":"test"}` |

**生成测试值的方法：**

1. **从代码中提取** - 查找代码注释、单元测试、示例数据中的值
2. **从字段语义推断** - 根据字段名含义生成合理值（如 `email` → `test@example.com`）
3. **从类型推断** - String用描述性文本，数字用合理范围值
4. **使用通用安全测试值** - 避免特殊字符，确保请求可正常发送

### 2.6 方法参数独立检查建议

分析多个方法时，可分别核对：

#### 步骤1：读取该方法的实际代码签名

应读取实际代码获取参数，避免仅凭方法名假设：

```
方法A: getDictionaryAll(String codeTypes)           → 1个参数
方法B: getCommonQuery(String searchJson, ...)       → 3个参数
方法C: executeCommand(String cmd, String args)      → 2个参数
```

#### 步骤2：独立追踪该方法的调用链到 Sink

不同方法可能有不同的 Sink 类型：

| 方法示例 | 调用链 | Sink 类型 |
|:---------|:-------|:----------|
| getCommonQuery | → DAO → SQL执行 | SQL |
| executeTask | → Runtime.exec() | COMMAND |
| fetchUrl | → HttpClient.get() | HTTP |
| parseXml | → DocumentBuilder.parse() | XML |
| getDictionaryAll | → Map.get() | 无敏感Sink |

#### 步骤3：判定该方法参数的可控性

根据该方法实际追踪到的 Sink 类型进行判定：

| Sink 类型 | 判定要点 |
|:----------|:---------|
| SQL | 参数是否拼接到 SQL |
| COMMAND | 参数是否传递到命令执行 |
| HTTP | 参数是否用于构造 URL |
| FILE | 参数是否用于文件路径 |
| XML | 参数是否传递到 XML 解析器 |
| 无敏感Sink | 标注"无敏感操作" |

#### 步骤4：输出该方法的独立判定结果

**禁止行为：**
- ❌ 禁止写"参考第1个接口的参数定义"
- ❌ 禁止复用其他方法的可控性结论
- ❌ 禁止假设所有方法都有相同的参数或 Sink 类型

### 2.7 简化版生成前的可选检查清单

| # | 检查项 | 建议执行 |
|:--|:-------|:---------|
| 1 | 读取该方法的代码签名，获取实际参数列表 | ☐ |
| 2 | 追踪该方法的调用链到最终使用点 | ☐ |
| 3 | 识别该方法的 Sink 类型（SQL/COMMAND/HTTP/FILE/XML/无） | ☐ |
| 4 | 判定该方法参数的可控性 | ☐ |
| 5 | 输出该方法的可控性判定表 | ☐ |

### 3. 追踪调用链

从入口方法开始，逐层追踪：

```
Controller/Action 层
    ↓ 调用
Service/Manager 层
    ↓ 调用
DAO/Repository 层
    ↓ 执行
SQL/数据库操作
```

**追踪规则：**

1. **识别方法调用** - 检查方法体中的 `this.xxx()` 或注入对象的方法调用
2. **跟踪依赖注入** - 识别 `@Autowired`、`@Resource`、构造器注入的对象
3. **追踪父类方法** - 如果调用 `super.xxx()` 或继承方法，追踪到父类
4. **记录参数传递** - 记录参数如何从上层传递到下层

### 4. 反编译支持

当源码不可用时，按运行环境中可用的反编译能力处理。可使用 `java_decompile`、CFR、`javap` 或其他可用工具，按输入类型和实际效果选择。

---

## 可选输出参考

以下模板和文件拆分只作为组织示例，可按实际写回方式调整。

| 场景 | 模板 | 文件命名 |
|------|------|---------|
| 第 1 个接口（完整版） | [OUTPUT_TEMPLATE_FULL.md](references/OUTPUT_TEMPLATE_FULL.md) | `{project_name}_trace_{method_name}_{YYYYMMDD_HHMMSS}.md` |
| 第 2+ 个接口（简化版） | [OUTPUT_TEMPLATE_SIMPLE.md](references/OUTPUT_TEMPLATE_SIMPLE.md) | `{project_name}_trace_{method_name}_{YYYYMMDD_HHMMSS}.md` |
| 多方法索引 | [OUTPUT_TEMPLATE_INDEX.md](references/OUTPUT_TEMPLATE_INDEX.md) | `{project_name}_trace_all_methods_{YYYYMMDD_HHMMSS}.md` |

**参考建议：**
- 所有【填写】占位符必须替换为实际内容
- 不同方法的参数和 Sink 结论应分别核对
- 多方法路由建议记录模块索引
- 通用规范参考: [java-shared/OUTPUT_STANDARD.md](../java-shared/OUTPUT_STANDARD.md)

### 多方法路由

入口类包含多个业务方法时，可按风险和证据价值拆成多个分析单元，也可以在同一条结论中分别列出；不要求固定文件结构。

**路由名说明：**
- 路由名从路由路径提取，去掉前缀斜杠和特殊字符
- 例如：`/biz/ws/userService` → `biz_ws_userService`
- 例如：`/api/user/login.action` → `api_user_login`

**执行流程：**

```
正在扫描入口类: UserQueryServiceImpl

✅ 发现 10 个入口方法

--- 方法 1/10: getBasicQuery ---
[生成独立报告: myproject_trace_getBasicQuery_20260204.md]

--- 方法 2/10: getAdvancedQuery ---
[生成独立报告: myproject_trace_getAdvancedQuery_20260204.md]

...

✅ 所有 10 个方法追踪完成
✅ 生成总索引: myproject_trace_all_methods_20260204.md
```

**总索引报告内容：**
```markdown
# /api/ws/userQuery Web Service 所有方法追踪索引

生成时间: 2026-02-04
入口类: UserQueryServiceImpl
方法总数: 10

## 方法清单

| # | 方法名 | 参数列表 | 详细报告 |
|:--|:-------|:---------|:---------|
| 1 | getBasicQuery | searchJson, pageJson, extend | [查看](myproject_trace_getBasicQuery_20260204.md) |
| 2 | getAdvancedQuery | searchJson, pageJson, extend | [查看](myproject_trace_getAdvancedQuery_20260204.md) |
| 3 | getDetailQuery | searchJson, pageJson, extend | [查看](myproject_trace_getDetailQuery_20260204.md) |
| ... | ... | ... | ... |
```

详细实现策略请参考：[multi-method-tracing.md](references/multi-method-tracing.md)

### 输出示例

#### 完整追踪链（适用于第 1 个接口）

完整的调用链追踪报告，包含所有层级、分支、变量追踪等内容。

````markdown
# 路由调用链追踪报告

**追踪路由**: `/admin/image/getImageCapture.action`
**生成时间**: 2026-02-04
**项目路径**: /path/to/project

---

## 1. HTTP 请求数据包

### 1.1 完整请求模板

```http
POST /admin/image/getImageCapture.action HTTP/1.1
Host: {{host}}
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID={{session}}

searchJson={{searchJson}}&pageJson={{pageJson}}&extend={{extend}}
```

### 1.2 参数详细定义

#### 顶层参数

| 参数名 | Java类型 | HTTP位置 | 必填 | 说明 |
|:-------|:---------|:---------|:-----|:-----|
| searchJson | String | Body | 是 | JSON格式，反序列化为 ImageCaptureBean |
| pageJson | String | Body | 是 | JSON格式，反序列化为 Page<ImageCapture> |
| extend | String | Body | 否 | 扩展参数 |

#### pageJson 内部结构 (Page<ImageCapture>)

| 字段名 | Java类型 | 说明 | 最终使用位置 |
|:-------|:---------|:-----|:-------------|
| orderBy | String | 排序字段 | **AbstractDao.findSql():234 - SQL拼接** |
| order | String | 排序方向 (asc/desc) | **AbstractDao.findSql():234 - SQL拼接** |
| pageSize | int | 每页条数 | 分页查询 |
| currentPage | int | 当前页码 | 分页查询 |

#### searchJson 内部结构 (ImageCaptureBean)

| 字段名 | Java类型 | 说明 |
|:-------|:---------|:-----|
| userBean | UserBean | 用户信息对象 |
| startTime | String | 开始时间 |
| endTime | String | 结束时间 |
| deviceIds | List<String> | 设备ID列表 |

### 1.3 测试用数据包示例

```http
POST /admin/image/getImageCapture.action HTTP/1.1
Host: 192.168.1.100:8080
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=ABC123

searchJson={"userBean":{"loginName":"admin"},"startTime":"2026-01-01","endTime":"2026-02-01"}&pageJson={"orderBy":"id","order":"desc","pageSize":10,"currentPage":1}&extend=
```

---

## 2. 调用链层级追踪

### [Level 1] Action 入口层

**文件**: `com/example/web/action/ImageCaptureAction.java:125`
**类名**: `ImageCaptureAction`
**方法签名**:
```java
public String getImageCapture(String searchJson, String pageJson, String extend)
```

**完整代码:**
```java
public String getImageCapture(String searchJson, String pageJson, String extend) {
    // pageJson 反序列化为 Page 对象
    Page<ImageCapture> page = (Page)JsonUtils.fromJson(pageJson, (new TypeToken<Page<ImageCapture>>() {
    }).getType(), (String)null);

    this.defaultImageCaptureSearchOrder(page);

    // searchJson 反序列化为 ImageCaptureBean 对象
    ImageCaptureBean searchBean = (ImageCaptureBean)JsonUtils.fromJson(searchJson, ImageCaptureBean.class, (String)null);

    if (searchBean.getUserBean() != null && StringUtil.isEmpty(searchBean.getUserBean().getHostLoginIp())) {
        String addressIp = WebServiceUtil.getWebServiceIp();
        if (StringUtil.isEmpty(addressIp)) {
            addressIp = searchBean.getUserBean().getLoginServerName();
        }
        searchBean.getUserBean().setHostLoginIp(addressIp);
    }

    searchBean.setSecordExcute(false);
    String json = WebServiceUtil.valiatePam((new TypeToken<ReturnMsgBean<ImageCapture>>() {
    }).getType(), new Object[]{page, searchBean});

    if (json == null) {
        // 关键调用: 传递 searchBean, page, extend 到 Manager 层
        json = this.imageCaptureManager.getImageCaptureJson(searchBean, page, extend);
    }

    return json;
}
```

**参数转换:**

| HTTP参数 | 转换后类型 | 转换后变量名 | 传递到下一层 |
|:---------|:-----------|:-------------|:-------------|
| pageJson (String) | Page<ImageCapture> | page | ✅ |
| searchJson (String) | ImageCaptureBean | searchBean | ✅ |
| extend (String) | String | extend | ✅ |

**Page对象关键字段:**
- `page.orderBy` ← pageJson.orderBy (String类型)
- `page.order` ← pageJson.order (String类型)

**下一层调用**: `this.imageCaptureManager.getImageCaptureJson(searchBean, page, extend)`

---

### [Level 2] Manager 服务层

**文件**: `com/example/service/ImageCaptureManager.java:89`
**类名**: `ImageCaptureManager`
**方法签名**:
```java
public String getImageCaptureJson(ImageCaptureBean searchBean, Page<ImageCapture> page, String extend)
```

**完整代码:**
```java
public String getImageCaptureJson(ImageCaptureBean searchBean, Page<ImageCapture> page, String extend) {
    // 关键调用: 将 page 传递给 DAO 层
    Page<ImageCapture> result = this.imageCaptureDao.getImageCapturePage(searchBean, page);
    return JsonUtils.toJson(result);
}
```

**参数传递:**

| 接收参数 | 类型 | 传递到下一层 |
|:---------|:-----|:-------------|
| searchBean | ImageCaptureBean | ✅ |
| page | Page<ImageCapture> | ✅ (含 orderBy, order) |
| extend | String | ❌ (未传递) |

**下一层调用**: `this.imageCaptureDao.getImageCapturePage(searchBean, page)`

---

### [Level 3] DAO 数据访问层

**文件**: `com/example/dao/ImageCaptureDao.java:56`
**类名**: `ImageCaptureDao`
**父类**: `AbstractDao<ImageCapture>`
**方法签名**:
```java
public Page<ImageCapture> getImageCapturePage(ImageCaptureBean searchBean, Page<ImageCapture> page)
```

**完整代码:**
```java
public Page<ImageCapture> getImageCapturePage(ImageCaptureBean searchBean, Page<ImageCapture> page) {
    String sql = buildQuerySql(searchBean);
    // 关键调用: 调用父类 AbstractDao.findSql()，传入 page 对象
    return super.findSql(sql, page);
}
```

**参数传递:**

| 接收参数 | 类型 | 传递到下一层 |
|:---------|:-----|:-------------|
| searchBean | ImageCaptureBean | ❌ (用于构建SQL) |
| page | Page<ImageCapture> | ✅ (传递给父类) |

**下一层调用**: `super.findSql(sql, page)` → 父类 `AbstractDao.findSql()`

---

### [Level 4] 父类基础层 (最终使用点)

**文件**: `com/example/dao/base/AbstractDao.java:234`
**类名**: `AbstractDao<T>`
**方法签名**:
```java
protected Page<T> findSql(String sql, Page<T> page)
```

**完整代码:**
```java
protected Page<T> findSql(String sql, Page<T> page) {
    if (page.getOrderBy() != null) {
        // ⚠️ 最终使用点: orderBy 和 order 直接拼接到 SQL 语句
        sql = sql + " ORDER BY " + page.getOrderBy() + " " + page.getOrder();
    }
    // 执行 SQL 查询
    return executeQuery(sql, page);
}
```

**参数最终使用:**

| 参数 | 类型 | 使用方式 | 代码位置 |
|:-----|:-----|:---------|:---------|
| page.getOrderBy() | String | **直接拼接到 SQL** | AbstractDao.java:235 |
| page.getOrder() | String | **直接拼接到 SQL** | AbstractDao.java:235 |

---

## 3. 调用链总结图

```
HTTP Request
│
├─ searchJson (String) ──→ ImageCaptureBean searchBean
│                              └─ userBean: UserBean
│                              └─ startTime: String
│                              └─ endTime: String
│
├─ pageJson (String) ────→ Page<ImageCapture> page
│                              ├─ orderBy: String ─────────────────────┐
│                              ├─ order: String ───────────────────────┤
│                              ├─ pageSize: int                        │
│                              └─ currentPage: int                     │
│                                                                      │
└─ extend (String) ──────→ (未向下传递)                                │
                                                                       │
┌──────────────────────────────────────────────────────────────────────┘
│
▼ 参数流向追踪

[L1] ImageCaptureAction.getImageCapture()
      │
      │  page (含 orderBy, order), searchBean
      ▼
[L2] ImageCaptureManager.getImageCaptureJson()
      │
      │  page (含 orderBy, order), searchBean
      ▼
[L3] ImageCaptureDao.getImageCapturePage()
      │
      │  page (含 orderBy, order)
      ▼
[L4] AbstractDao.findSql()
      │
      └──→ sql = sql + " ORDER BY " + page.getOrderBy() + " " + page.getOrder()
           ▲                              ▲
           │                              │
           └── orderBy 直接拼接 ──────────┴── order 直接拼接
```

---

## 4. 参数变量名追踪表（核心）

**追踪同一参数在不同类中的变量名变化：**

### 4.1 pageJson.orderBy 参数追踪

| 层级 | 类名 | 变量名 | 类型 | 代码位置 | 说明 |
|:-----|:-----|:-------|:-----|:---------|:-----|
| HTTP | - | `pageJson` | String | 请求Body | 原始JSON字符串 |
| L1 | ImageCaptureAction | `pageJson` → `page.orderBy` | Page.orderBy: String | :125 | JsonUtils.fromJson()反序列化 |
| L2 | ImageCaptureManager | `page.orderBy` | Page.orderBy: String | :89 | 参数名不变，直接传递 |
| L3 | ImageCaptureDao | `page.orderBy` | Page.orderBy: String | :56 | 参数名不变，传递给父类 |
| L4 | AbstractDao | `page.getOrderBy()` | String | :235 | **最终使用: SQL拼接** |

### 4.2 pageJson.order 参数追踪

| 层级 | 类名 | 变量名 | 类型 | 代码位置 | 说明 |
|:-----|:-----|:-------|:-----|:---------|:-----|
| HTTP | - | `pageJson` | String | 请求Body | 原始JSON字符串 |
| L1 | ImageCaptureAction | `pageJson` → `page.order` | Page.order: String | :125 | JsonUtils.fromJson()反序列化 |
| L2 | ImageCaptureManager | `page.order` | Page.order: String | :89 | 参数名不变 |
| L3 | ImageCaptureDao | `page.order` | Page.order: String | :56 | 参数名不变 |
| L4 | AbstractDao | `page.getOrder()` | String | :235 | **最终使用: SQL拼接** |

### 4.3 searchJson 参数追踪

| 层级 | 类名 | 变量名 | 类型 | 代码位置 | 说明 |
|:-----|:-----|:-------|:-----|:---------|:-----|
| HTTP | - | `searchJson` | String | 请求Body | 原始JSON字符串 |
| L1 | ImageCaptureAction | `searchJson` → `searchBean` | ImageCaptureBean | :128 | JsonUtils.fromJson()反序列化 |
| L2 | ImageCaptureManager | `searchBean` | ImageCaptureBean | :89 | 参数名不变 |
| L3 | ImageCaptureDao | `searchBean` | ImageCaptureBean | :56 | **最终使用: buildQuerySql()** |

### 4.4 变量名变化示例（当参数名在不同层改变时）

```
HTTP: pageJson (String)
       ↓ JsonUtils.fromJson()
L1 ImageCaptureAction: page (Page<ImageCapture>)
       ↓ 方法参数传递
L2 ImageCaptureManager: page (Page<ImageCapture>)  ← 同名
       ↓ 方法参数传递
L3 ImageCaptureDao: page (Page<ImageCapture>)  ← 同名
       ↓ super.findSql(sql, page)
L4 AbstractDao: page (Page<T>)  ← 泛型类型变化
       ↓ page.getOrderBy()
最终使用: sql = sql + " ORDER BY " + page.getOrderBy()
```

### 4.5 完整参数追踪汇总

| 原始HTTP参数 | L1变量名 | L2变量名 | L3变量名 | L4变量名 | 最终使用 |
|:-------------|:---------|:---------|:---------|:---------|:---------|
| pageJson | page | page | page | page | page.getOrderBy() → SQL拼接 |
| pageJson.orderBy | page.orderBy | page.orderBy | page.orderBy | page.getOrderBy() | SQL ORDER BY 子句 |
| pageJson.order | page.order | page.order | page.order | page.getOrder() | SQL ORDER BY 子句 |
| searchJson | searchBean | searchBean | searchBean | - | buildQuerySql() |
| extend | extend | - | - | - | 未向下传递 |
````

---

## 5. 参数实际使用检查（CRITICAL - 防止漏洞误判）

**追踪每个参数从 HTTP 入口到最终使用点，判定参数是否真正参与敏感操作。**

**此检查对于准确判定漏洞至关重要，可避免将"参数传递但未使用"的情况误判为漏洞。**

### 5.1 检查说明

| 状态 | 含义 | 对漏洞判定的作用 |
|:-----|:-----|:-----------------|
| ✅ 被使用 | 参数值直接或间接参与敏感操作 | 必须进一步检测是否存在漏洞 |
| ❌ 未使用 | 参数被传递但未参与敏感操作（被硬编码覆盖/被忽略） | **排除漏洞** |
| ⚠️ 部分使用 | 参数的部分字段被使用，部分未使用 | 仅检测被使用的字段 |

### 5.2 各漏洞类型的"硬编码覆盖"场景

| 漏洞类型 | 参数 | 硬编码覆盖场景 | 结论 |
|:---------|:-----|:---------------|:-----|
| **SQL 注入** | `page.orderBy` | SQL 已硬编码 `order by createTime desc` | 参数未使用 |
| **命令注入** | `cmd` | 代码硬编码 `Runtime.exec("ls -la")` | 参数未使用 |
| **SSRF** | `url` | 代码硬编码 `httpClient.get("http://internal/api")` | 参数未使用 |
| **文件操作** | `path` | 代码硬编码 `new File("/tmp/fixed.txt")` | 参数未使用 |
| **XXE** | `xml` | 代码使用固定 XML 模板 | 参数未使用 |
| **表达式注入** | `expr` | 代码硬编码表达式 `SpEL.parse("#{fixed}")` | 参数未使用 |

### 5.3 参数使用检查表（输出模板）

```markdown
## 参数实际使用检查

| 参数 | Sink类型 | 覆盖类型 | 覆盖条件 | 可控性结论 | 可控场景 |
|:-----|:---------|:---------|:---------|:-----------|:---------|
| page.orderBy | SQL ORDER BY | 条件覆盖 | `isEmpty(orderBy)` | ⚠️ 条件可控 | 非空时可控 |
| page.order | SQL ORDER BY | 无覆盖 | - | ✅ 完全可控 | 任意值 |
| cmd | Runtime.exec | 无覆盖 | - | ✅ 完全可控 | 任意值 |
| url | HTTP请求 | 安全检查覆盖 | `!isInternalUrl(url)` | ⚠️ 条件可控 | 外网URL时可控 |
| path | File操作 | 白名单覆盖 | `!allowedPaths.contains()` | ⚠️ 白名单内可控 | /tmp, /data 等 |
| searchBean.keyword | SQL WHERE | 无条件覆盖 | 总是覆盖 | ❌ 不可控 | 无 |
```

**可控性结论说明：**

| 结论 | 含义 | 审计要求 |
|:-----|:-----|:---------|
| ✅ 完全可控 | 参数无任何覆盖，用户输入直接到达 Sink | 必须审计 Sink 点安全性 |
| ⚠️ 条件可控 | 参数在特定条件下可控 | 需验证绕过条件后审计 |
| ❌ 不可控 | 参数被无条件覆盖或安全处理 | 可排除该参数的漏洞 |

### 5.4 通用覆盖条件识别规则（适用于所有漏洞类型）

**追踪到参数赋值操作后，可检查覆盖条件，此思路适用于任何类型的参数：**

| 覆盖类型 | 代码特征 | 可控性判定 | 适用场景 |
|:---------|:---------|:-----------|:---------|
| **无条件覆盖** | `x = "hardcoded";` (不在 if 内) | ❌ 不可控 | 所有漏洞类型 |
| **空值保护覆盖** | `if (isEmpty(x)) { x = default; }` | ⚠️ 非空时可控 | 所有漏洞类型 |
| **null保护覆盖** | `if (x == null) { x = default; }` | ⚠️ 非null时可控 | 所有漏洞类型 |
| **白名单覆盖** | `if (!list.contains(x)) { x = default; }` | ⚠️ 白名单内可控 | 所有漏洞类型 |
| **安全检查覆盖** | `if (!isAllowed(x)) { x = safe; }` | ⚠️ 绕过检查时可控 | SSRF/文件/命令 |
| **格式校验覆盖** | `if (!isValid(x)) { x = default; }` | ⚠️ 符合格式时可控 | 所有漏洞类型 |
| **条件分支覆盖** | `if (cond) { x = default; }` | ⚠️ 条件不满足时可控 | 所有漏洞类型 |

**常见覆盖条件识别（通用）：**

| 条件类型 | 识别模式 | 可控场景 |
|:---------|:---------|:---------|
| **空值检查** | `isEmpty()`, `isBlank()`, `== null`, `length() == 0` | 非空时可控 |
| **白名单检查** | `contains()`, `Arrays.asList()`, `allowedList.contains()` | 白名单内可控 |
| **黑名单检查** | `!contains()`, `blacklist.contains()` → 拒绝 | 不在黑名单时可控 |
| **格式校验** | `matches()`, `Pattern.compile()`, `isValid()` | 符合格式时可控 |
| **安全检查** | `isAllowed()`, `isSafe()`, `checkSecurity()` | 绕过检查时可控 |
| **范围检查** | `x > min && x < max`, `inRange()` | 范围内可控 |

**原有硬编码覆盖检测规则（仍然适用）：**

| 敏感操作类型 | 硬编码覆盖判断方法 | 示例 |
|:-------------|:-------------------|:-----|
| SQL ORDER BY | 检查 SQL 字符串是否已包含 `order by` | `sql + " order by id desc"` |
| SQL WHERE | 检查条件是否使用参数化 `#{}` 或硬编码值 | `WHERE status = 1` |
| 命令执行 | 检查命令字符串是否使用硬编码命令 | `exec("ls -la")` |
| HTTP 请求 | 检查 URL 是否使用硬编码地址 | `get("http://fixed.com")` |
| 文件操作 | 检查路径是否使用硬编码路径 | `new File("/tmp/log.txt")` |
| XML 解析 | 检查 XML 是否来自固定模板 | `parse(FIXED_XML)` |

### 5.5 硬编码覆盖详情输出格式

**当发现参数被硬编码覆盖时，应说明详情：**

```
### 硬编码覆盖详情

#### {参数名} - 被硬编码覆盖

**代码位置**: `{ClassName}.java:{line}`

**覆盖代码**: {展示硬编码覆盖的代码片段}

**判定**:
- {参数}被传递到{方法}
- 但{敏感操作}已经包含硬编码值
- **结论**: ❌ 参数未使用，不存在漏洞
```

### 5.6 参数实际使用检查清单

**输出追踪报告前，可按需完成以下检查：**

| # | 检查项 | 状态 |
|:--|:-------|:-----|
| 1 | 识别所有传递到最终层的参数 | ☐ |
| 2 | 确定每个参数的敏感操作类型 | ☐ |
| 3 | 检查是否存在硬编码覆盖 | ☐ |
| 4 | 标注每个参数的实际使用状态 | ☐ |
| 5 | 对"被硬编码覆盖"的参数输出详情 | ☐ |
| 6 | **检查覆盖条件语义，输出可控性结论** | ☐ |

---

## 6. 参数可控性判定（CRITICAL - 通用漏洞判定依据）

**适用于所有漏洞类型：SQL注入、命令注入、SSRF、文件操作、XXE、表达式注入等。**

**详细判定原则请参考：[CONTROLLABILITY_ANALYSIS.md](references/CONTROLLABILITY_ANALYSIS.md)**

### 6.1 核心判定流程

```
1. 追踪参数从 HTTP 入口到 Sink 的完整路径
2. 识别路径上所有对参数的赋值/覆盖操作
3. 检查覆盖操作的条件语义（识别代码意图，非模式匹配）
4. 输出可控性结论
```

### 6.2 覆盖类型与可控性

| 覆盖类型 | 判定标准 | 可控性结论 |
|:---------|:---------|:-----------|
| **无覆盖** | 参数直接传递到 Sink | ✅ 完全可控 |
| **无条件覆盖** | 赋值不在任何条件内 | ❌ 不可控 |
| **条件覆盖** | 赋值在条件内，需判定语义 | ⚠️ 条件可控 |

### 6.3 条件语义判定（关键）

**根据代码语义识别，而非匹配固定方法名：**

| 语义类型 | 判断方法 | 可控场景 |
|:---------|:---------|:---------|
| 空值保护 | 条件判断参数是否为空，为空时设默认值 | 非空时可控 |
| 白名单验证 | 条件判断参数是否在允许列表中 | 白名单内可控 |
| 安全检查 | 条件判断参数是否安全 | 绕过检查时可控 |

### 6.4 输出格式

**有多个参数时建议整理可控性判定表：**

```markdown
| 参数 | Sink类型 | 覆盖类型 | 覆盖条件 | 可控性结论 | 可控场景 |
|:-----|:---------|:---------|:---------|:-----------|:---------|
| {name} | {sink} | {type} | {condition} | {✅/⚠️/❌} | {scenario} |
```

**形成结论时说明可控性汇总：**

```markdown
| 可控性类型 | 参数列表 | 审计要求 |
|:-----------|:---------|:---------|
| ✅ 完全可控 | {list} | 必须审计 Sink 安全性 |
| ⚠️ 条件可控 | {list} | 需验证绕过条件 |
| ❌ 不可控 | {list} | 可排除漏洞可能 |
```

### 6.5 Sink 类型

| Sink | 说明 |
|:-----|:-----|
| SQL | SQL 拼接/执行 |
| COMMAND | 系统命令执行 |
| HTTP | HTTP 请求发起 |
| FILE | 文件读写操作 |
| XML | XML 解析 |
| LDAP | LDAP 查询 |
| EXPRESSION | 表达式解析 |
| DESERIALIZE | 反序列化 |
| RESPONSE | 响应输出 |
| PATH | 路径拼接 |

---

## 7. 分支条件追踪（CRITICAL - 避免漏洞误判）

**追踪调用链时，建议记录关键条件分支，以便识别代码是否真的会执行。**

**详细判定原则请参考：[BRANCH_TRACING.md](references/BRANCH_TRACING.md)**

### 7.1 核心判定流程

```
1. 识别代码中的条件分支（if/else/switch）
2. 检查每个分支的执行内容
3. 判定敏感操作在哪些分支中执行
4. 输出执行路径结论
```

### 7.2 建议识别的分支类型

**根据代码语义识别，而非匹配固定方法名：**

| 分支类型 | 语义特征 | 追踪要点 |
|:---------|:---------|:---------|
| 环境/平台分支 | 根据运行环境选择不同路径 | 标注各环境执行内容 |
| 安全检查分支 | 对输入进行安全验证 | 标注拦截条件 |
| 功能开关分支 | 根据配置决定是否执行 | 标注开关状态影响 |
| 空值/异常分支 | 检查参数有效性 | 标注提前退出条件 |
| 权限判断分支 | 检查用户权限 | 标注权限要求 |

### 7.3 提前退出点识别

| 退出类型 | 语义 | 必须标注 |
|:---------|:-----|:---------|
| 安全拦截退出 | 安全检查失败，拒绝继续 | ⚠️ 安全拦截 |
| 空值保护退出 | 参数无效，提前返回 | ⚠️ 提前退出 |
| 异常抛出退出 | 条件不满足，抛出异常 | ⚠️ 异常退出 |

### 7.4 输出格式

**有复杂分支时说明分支结构：**

```markdown
methodName(param)
    ├─ [if 条件A] → 分支A执行内容
    │      └─→ 敏感操作 ⚠️
    └─ [else] → 默认分支 / return / throw
```

**形成结论时说明执行路径：**

```markdown
| 路径 | 条件 | 敏感操作 | 可利用性 |
|:-----|:-----|:---------|:---------|
| 路径A | {条件} | ✅ 执行 | 可利用 |
| 路径B | {条件} | ❌ 不执行 | 不可利用 |
```

---

## 追踪策略

### 策略 1: 依赖注入追踪

识别 Spring/Struts 的依赖注入：

```java
// Spring
@Autowired
private ImageCaptureManager imageCaptureManager;

// Struts
private ImageCaptureService faceCaptureService;
public void setImageCaptureService(ImageCaptureService service) {
    this.faceCaptureService = service;
}
```

追踪 `imageCaptureManager.xxx()` 调用时，定位到 `ImageCaptureManager` 类。

### 策略 2: 继承链追踪

当调用 `super.xxx()` 或父类方法时：

```java
public class ImageCaptureDao extends AbstractDao<ImageCapture> {
    public Page<ImageCapture> query(Page<ImageCapture> page) {
        return super.findSql(sql, page);  // 追踪到 AbstractDao
    }
}
```

追踪步骤：
1. 识别 `extends AbstractDao`
2. 在父类中查找 `findSql` 方法
3. 继续追踪父类的父类（如有）

### 策略 3: 接口实现追踪

当调用接口方法时：

```java
@Autowired
private UserService userService;  // 接口类型

userService.getUser(id);  // 需要找到实现类
```

追踪步骤：
1. 识别 `UserService` 是接口
2. 查找 `implements UserService` 的类
3. 定位到实现类的方法

### 策略 4: MyBatis/Hibernate 追踪

对于 ORM 框架：

**MyBatis:**
```java
@Mapper
public interface UserMapper {
    List<User> selectByPage(@Param("page") Page page);
}
```
追踪到对应的 XML 文件中的 SQL 定义。

**Hibernate:**
```java
session.createQuery("FROM User WHERE id = " + id);
```
直接在代码中识别 HQL/SQL。

---

## 反编译工具使用

### 何时反编译

| 场景 | 操作 |
|:-----|:-----|
| .java 源码存在 | 直接读取检查 |
| 只有 .class 文件 | 使用 decompile_file |
| 整个项目只有 .class | 使用 decompile_directory |
| 父类在 JAR 包中 | 先解压 JAR，再 decompile_file |

### 反编译命令参考

可使用运行环境中可用的反编译工具。单个类可优先读取 `javap`，需要可读源码时可选择 `java_decompile`、CFR 或现有反编译产物。

---

## 限制与边界

**仅执行以下操作：**
- 追踪指定路由的调用链
- 输出每层的文件位置和方法签名
- 记录参数传递关系
- 生成 HTTP 请求模板

**不执行以下操作：**
- 不进行安全漏洞检测
- 不提供修复方案
- 不判定漏洞等级
- 不检查业务逻辑正确性
