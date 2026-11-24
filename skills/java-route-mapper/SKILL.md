---
name: java-route-mapper
metadata:
  tags: [代码审计, java, 路由, 参数映射, 接口梳理]
description: Java Web 源码路由与参数映射分析工具。用于按证据和审计收益建立可达入口、路由、参数和处理器映射；不强制固定输出目录或一次性导出所有接口。
---

# Java Source Route & Parameter Mapper

从 Java Web 项目源码中**提取**所有 HTTP 路由与请求参数结构，为下游漏洞审计 Skill 提供完整的路由数据。**不进行安全漏洞评估、代码质量分析或任何路由提取范围之外的内容输出。**

## 适用场景

适合需要建立 Java Web 入口、路由、参数和处理器映射，供鉴权审计、调用链追踪或专项漏洞审计使用。

## 不适用场景

如果只需要分析一个已知 Controller、Servlet 或 Web Service，不必为了完整性枚举全部项目；如果入口无法确认，应先补充项目结构证据。

## 核心判断

路由映射的目标是建立可追踪、可验证的入口清单，而不是追求字符串数量。优先业务入口、动态参数、鉴权边界和能定位到处理器的路由。

## 证据标准

- 路由需要绑定框架配置或注解、处理器位置和参数来源。
- Web Service 路径必须来自配置，不能根据类名推断。
- 动态路由需要记录约束和实例来源。
- 无法定位处理器或参数时标记待验证，不虚构完整模板。

## 决策树

- 框架配置明确：按配置和注解提取路由。
- 路由由通配符或内部 Servlet 分发：先识别分发逻辑，再列模式族和实例。
- 处理器无法定位：保留路由线索并标记缺口。
- 参数来源不明确：记录输入类型和待追踪位置。
- 路由数量过大：优先有业务语义、上传、查询、管理和高危参数的路由。

## 常见误判

- 把静态资源当成业务路由。
- 把类名或 endpoint id 推断成 Web Service 路径。
- 把框架默认映射当成实际暴露。
- 为了“完整”生成没有源码依据的路由。
- 把请求模板当成可利用 PoC。

## 路由覆盖建议

优先记录实际可达、与当前审计目标相关的入口，并说明覆盖范围和未解析原因。接口数量较大时可按模块、风险或证据价值组织，不要求一次性展开全部路由。

---

## 路由识别建议

以下内容是识别和核对路由的候选方法，不要求按固定格式输出。

---

### 1. 通配符与动态路由

通配符路由可作为模式族和实例列表整理，避免重复完整模板造成 token 浪费。

一般不需要为每个展开后的 URL 重复完整模板，可按当前证据需要展开参数结构。

#### 1.1 Struts2 通配符路由

**适用场景**（struts.xml 中存在）：
- `name="*_*"` 双通配 / `name="user_*"` 单通配 / `name="*"` 全匹配

**识别建议：**

1. 识别通配符配置：
   ```xml
   <action name="*_*" class="{1}Action" method="{2}">
   ```
2. 反编译该 namespace 下所有 Action 类（排除 getter/setter、ActionSupport 继承方法）
3. 输出**模式族 + 实例列表**：
   ```markdown
   === Pattern: {action}_{method}.action (namespace: /admin) ===
   入口模板: {ActionClass}.{methodName}()
   HTTP 方法: POST
   Content-Type: application/x-www-form-urlencoded
   参数来源: 各 Action 类的字段（下游 agent-5 反编译时提取）

   展开实例（共 {N} 个）:
   - /admin/user_login.action → UserAction.login()
   - /admin/user_logout.action → UserAction.logout()
   - /admin/user_register.action → UserAction.register()
   ```

#### 1.2 Spring MVC 路径变量

路径变量（`{id}`、`/**`）**不属于通配符展开**——同一 controller 方法处理全部路径变量值，无需展开实例。直接按普通路由格式输出，参数结构中标注 `Path: {id}:Long`。

#### 1.3 JAX-RS 路径参数

同 1.2，路径参数（`@PathParam`）按普通路由格式输出，不展开实例。

#### 1.4 Servlet URL Pattern 通配符

适用场景：`/api/*`、`*.do` 等。若 Servlet 使用 `request.getPathInfo()` 内部分发到不同方法，可考虑按**模式族 + 实例列表**组织结果（参考 1.1 格式）；否则按普通路由处理。

---

### CRITICAL 2: Web Service 方法完整输出规则

#### 2.1 配置文件优先原则

**Web Service 的 URL 路径建议从配置文件中核对，避免只根据类名或 endpoint id 推断。**

**解析优先级（按顺序执行）：**

1. **读取配置文件** - applicationContext.xml 或其他 Spring 配置
2. **提取 address 属性** - 这是 Web Service 路径的唯一真实来源
3. **验证 Servlet 映射** - 从 web.xml 获取 /ws/* 或 /services/*
4. **组装完整 URL** - 上下文路径 + Servlet映射 + address
5. **反编译实现类** - 仅用于提取方法签名，不用于推断路径

**URL 组成公式：**
```
完整URL = 上下文路径 + web.xml中的Servlet映射 + address属性值

示例: /myapp + /services/ + /UserApi = /myapp/services/UserApi
```

**错误示例（建议避免）：**
- ❌ 根据类名推断: `UserServiceImpl` → `/UserService`
- ❌ 根据 id 推断: `userWebService` → `/userWebService`
- ✅ 读取配置: `address="/UserApi"` → `/myapp/services/UserApi`

#### 2.2 CXF/JAX-WS 服务

**识别建议：**

1. **从配置文件获取所有 endpoint**
   ```xml
   <jaxws:endpoint id="userService"
                   implementor="#userServiceImpl"
                   address="/UserService"/>
   ```

2. **反编译每个 Service 实现类**

3. **提取所有 public 方法** - 方法名、参数列表、返回类型

4. **为每个方法记录完整的方法签名和参数列表**

5. **记录配置来源** - 配置文件路径、行号、address 属性值、implementor 类名

#### 2.3 Axis/Axis2 服务

**识别建议：**

1. **读取 server-config.wsdd 或 services.xml**
   ```xml
   <service name="UserService" provider="java:RPC">
     <parameter name="className" value="com.example.UserService"/>
   </service>
   ```

2. **提取服务名和实现类**

3. **反编译实现类获取方法列表**

4. **URL 组成：** `/axis/services/{serviceName}`

#### 2.4 executeInterface 类型服务特殊处理

对于使用 interfaceId 参数路由的通用执行接口：

1. **反编译实现类，查找所有 interfaceId 定义**
2. **为每个 interfaceId 记录独立的参数结构**

---

### 3. 容易造成误判的省略方式

以下写法容易隐藏覆盖缺口，分析时尽量避免：

| 禁止模式 | 错误示例 | 正确做法 |
|:---------|:---------|:---------|
| 使用"等"省略 | `LoginAction, UserAction等` | 列出全部 Action |
| 使用"..."省略 | `method1, method2, ...` | 列出全部方法 |
| 使用"其他"省略 | `以及其他20个方法` | 列出全部20个方法 |
| 使用"更多"省略 | `更多接口请查看源码` | 直接列出所有接口 |
| 使用占位符 | `{action}_{method}.action` | 展开为实际 URL |
| 使用范围表示 | `001 ~ 050` | 逐个列出 001, 002, ..., 050 |
| 描述替代列表 | `方法列表: 用户管理相关` | 列出具体方法名 |
| 只给 WSDL 地址 | `请通过 WSDL 查看可用方法` | 列出所有 SOAP 方法 |
| 只列类名不列方法 | `UserAction 支持多个方法` | 列出每个方法的完整模板 |

---

### 4. 各框架的路由识别示例

#### 4.1 Struts2 路由

```markdown
=== [1] login_login.action ===
URL: `/admin/login_login.action`
方法: LoginAction.login()
HTTP 方法: POST
Content-Type: application/x-www-form-urlencoded

参数结构:
  Body: loginName (String), password (String)
```

#### 4.2 Spring MVC 路由

```markdown
=== [1] GET /api/users/{id} ===
位置: UserController.getUser (UserController.java:45)
HTTP 方法: GET
URL 路径: /api/users/{id}

参数结构:
  Path: {id} (Long) - 用户ID
  Header: Authorization - Bearer Token
```

#### 4.3 JAX-RS 路由

```markdown
=== [1] GET /rest/users/{userId} ===
位置: UserResource.getUser (UserResource.java:32)
HTTP 方法: GET
URL 路径: /rest/users/{userId}

参数结构:
  Path: {userId} (Long)
  Query: includeOrders (boolean, 可选)
```

#### 4.4 Servlet 路由

```markdown
=== [1] POST /api/upload ===
位置: UploadServlet.doPost (UploadServlet.java:28)
HTTP 方法: POST
URL 路径: /api/upload

参数结构:
  Body: multipart/form-data
    - file (File) - 上传文件
    - description (String) - 文件描述
```

#### 4.5 Web Service (SOAP) 方法

```markdown
### UserService (共 5 个方法)

- **配置文件**: applicationContext.xml:42
- **address 属性**: /UserApi
- **完整 URL**: /myapp/services/UserApi

=== [WS-1] login ===
方法签名: login(String loginName, String password)
返回类型: String

参数结构:
  Body: SOAP XML
    - loginName (String) - 登录名
    - password (String) - 密码
```

---

### 5. 覆盖检查建议

#### 5.1 数量一致性检查

| 检查项 | 计算公式 | 通过条件 |
|:-------|:---------|:---------|
| Struts2 路由 | 实际接口数 ÷ Action类数 | ≥ 3 |
| Spring MVC 接口 | 实际接口数 ÷ Controller类数 | ≥ 2 |
| JAX-RS 接口 | 实际接口数 ÷ Resource类数 | ≥ 2 |
| Servlet 接口 | 实际接口数 ÷ Servlet类数 | ≥ 1 |
| Web Service 方法 | 实际接口数 ÷ 反编译获得的方法数 | = 100% |

#### 5.2 省略词检测

扫描输出内容，检测到任何省略标志时必须替换为完整内容。

#### 5.3 文件完整性检查

- [ ] 主索引中每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的路由和参数信息（不是摘要）
- [ ] Web Service 索引中的每个服务都有完整的方法列表
- [ ] 没有"详见xxx"但 xxx 文件不存在的情况

#### 5.4 发现覆盖缺口时的处理

1. 标记缺失的入口或参数类型
2. 按当前证据价值选择继续反编译、回看源码或保留待验证项
3. 在结论中说明覆盖边界

---

### 6. 覆盖检查清单

形成结论前可检查：

#### 6.1 模块完整性检查

```markdown
□ 主索引中列出的每个模块都已生成对应的详情文件

  演示案例：
  ==========
  假设主索引文件的"模块索引"表格如下：

  | 模块 | 文件 | 接口数量 |
  |:-----|:-------|:-----|
  | admin | [admin/myapp_module_admin.md](admin/myapp_module_admin.md) | 218 |
  | user | [user/myapp_module_user.md](user/myapp_module_user.md) | 85 |
  | api | [api/myapp_module_api.md](api/myapp_module_api.md) | 45 |

  验证步骤：
  1. 检查 admin/myapp_module_admin.md 是否存在
  2. 检查 user/myapp_module_user.md 是否存在
  3. 检查 api/myapp_module_api.md 是否存在
  4. 确认模块数量(3) = 实际文件数量(3)

□ Web Service 索引中的每个服务都已生成对应的详情文件

□ 没有"详见xxx"但xxx文件不存在的情况
```

#### 6.2 交叉验证清单

```markdown
□ 文件数量一致性
  如果选择按模块拆分记录，主索引中的模块和实际记录范围应能对应。

□ 文件名一致性
  如果使用链接或文件引用，目标应能解析。

□ 链接有效性
  演示案例：点击主索引中的 [admin/myapp_module_admin.md] 链接应能成功打开
```

#### 6.3 内容完整性检查

```markdown
□ 每个详情文件都包含：
  - 模块概览（项目名称、上下文路径、框架）
  - 框架配置（配置文件位置）
  - 路由详细列表（每个接口的完整信息）

□ 对于空模块（无路由的模块）：
  演示案例：
  ==========
  某模块 upload 只有静态资源，没有业务路由

  正确做法：仍然生成 upload/myapp_module_upload.md
  ```markdown
  # MyApp - upload 模块详情

  ## 模块概览
  该模块主要用于静态文件上传，未检测到业务路由。

  ## 检查结果
  - WEB-INF目录：不存在
  - 配置文件：无
  - 路由接口：无
```

  错误做法：跳过不生成文件
```

#### 6.4 执行验证命令

**演示案例：在完成所有文件生成后，运行以下命令验证**

```bash
# 假设项目名称为 myapp，输出目录为 route_mapper/，生成的文件如下：
# route_mapper/myapp_route_mapper_20260129.md       (主索引)
# route_mapper/admin/myapp_module_admin_20260129.md  (admin模块)
# route_mapper/user/myapp_module_user_20260129.md    (user模块)
# route_mapper/api/myapp_module_api_20260129.md      (api模块)

# 验证命令1: 检查生成的模块子目录和文件
find route_mapper/ -name "*_module_*.md" -type f
# 预期输出：应该看到3个模块详情文件

# 验证命令2: 从主索引中提取所有引用的文件路径
grep -oP '[a-z]+/myapp_module_[^)]*md' route_mapper/myapp_route_mapper_20260129.md | sort -u

# 验证命令3: 检查引用的文件是否都存在
grep -oP '[a-z]+/myapp_[^)]*md' route_mapper/myapp_route_mapper_20260129.md | while read f; do
  if [ ! -f "route_mapper/$f" ]; then
    echo "❌ 缺失文件: route_mapper/$f"
  else
    echo "✅ 存在文件: route_mapper/$f"
  fi
done
```

#### 6.5 完成确认

**演示案例：完整的检查流程**

```markdown
假设分析了一个名为 myshop 的电商项目，包含以下模块：

步骤1: 生成主索引文件
  ✅ route_mapper/myshop_route_mapper_20260129.md

步骤2: 检查主索引中的模块列表
  主索引显示：product, order, user, payment (4个模块)

步骤3: 验证模块子目录和详情文件是否存在
  ✅ route_mapper/product/myshop_module_product_20260129.md
  ✅ route_mapper/order/myshop_module_order_20260129.md
  ✅ route_mapper/user/myshop_module_user_20260129.md
  ✅ route_mapper/payment/myshop_module_payment_20260129.md

步骤4: 生成README文档（**仅 standalone 模式**；pipeline/多 agent 模式下由 agent-1-merge 统一生成，worker 跳过此步骤）
  ✅ route_mapper/myshop_README_20260129.md

步骤5: 执行验证命令
  $ find route_mapper/ -name "*_module_*.md" -type f | wc -l
  4 (与主索引中模块数量一致)

步骤6: 确认完成
  所有检查项通过 → 可以标记任务完成
```

如果选择生成文件，可在结束前检查：

- [ ] 主索引文件已生成（pipeline 模式下由 agent-1-merge 生成，worker 跳过）
- [ ] README说明文档已生成（pipeline 模式下由 agent-1-merge 生成，worker 跳过）
- [ ] 主索引中列出的每个模块都有对应的详情文件
- [ ] 每个详情文件都包含完整的路由信息（或明确说明无路由）
- [ ] 所有文件链接可访问
- [ ] 已通过验证命令检查

发现缺失内容时，可补充对应分析、修正引用或在结论中标记覆盖缺口。

---

## 工作流程

### 1. 项目扫描初始化

```
输入: 项目源码路径
       可选: 项目上下文路径、已知框架信息
```

**初始化步骤：**

1. 识别项目类型和框架（通过配置文件和目录结构）- **支持多框架混合项目**
2. 确定路由加载方式（注解驱动 / XML 配置 / 混合）
3. 提取上下文路径和基础 URL

### 2. 框架识别与任务制定

**多框架支持：** 一个项目可能同时使用多种 Web 框架，需要分别识别并制定分析任务。

| 框架 | 识别特征 | 参考资料 |
|------|---------|---------|
| Spring MVC | `@Controller`、`@RequestMapping` | [SPRING_MVC.md](references/SPRING_MVC.md) |
| Spring Boot | `application.properties/yml`、Spring Boot starter | [SPRING_MVC.md](references/SPRING_MVC.md) |
| Servlet | `web.xml`、`@WebServlet` | [SERVLET.md](references/SERVLET.md) |
| JAX-RS | `@Path`、`@GET`、`@POST` | [JAXRS.md](references/JAXRS.md) |
| Struts 2 | `struts.xml` | [STRUTS.md](references/STRUTS.md) |
| CXF Web Services | `/ws/*`、`@WebService`、`applicationContext.xml` | [WEBSERVICE.md](references/WEBSERVICE.md) |

**任务制定规则：**
- 检测到的每个框架都生成独立的分析任务
- 任务按执行顺序排列（框架初始化 → 路由扫描 → 参数解析）
- 混合配置（注解+XML）需要同步分析两种方式

### 3. 路由枚举

扫描项目源码，提取所有对外可访问的 HTTP 路由。

**扫描范围：**
- `@Controller` / `@RestController` 类
- `@RequestMapping` 及其变体注解
- Servlet 配置（web.xml、@WebServlet）
- JAX-RS 注解（@Path、@GET、@POST 等）
- Struts2 Action 配置
- Web Service 端点配置

**输出信息：**
- HTTP 方法
- URL 路径（完整路径）
- 对应的控制器类和方法

### 4. 参数结构解析

对每个路由解析其参数结构。

**参数来源：**
- **Path 变量**：`@PathVariable`、`@PathParam`
- **Query 参数**：`@RequestParam`、`@QueryParam`
- **Body 参数**：`@RequestBody`、请求对象、Form 表单
- **Header 参数**：`@RequestHeader`、`@HeaderParam`
- **Cookie 参数**：`@CookieValue`、`@CookieParam`

**参数类型解析：**
- 基本类型（String、int、long 等）
- 对象类型（POJO）
- 集合类型（List、Map、Set）
- 枚举类型

### 5. 反编译支持（必要时）

当接口定义或方法签名位于已编译的 .class 文件或第三方 JAR 中时：

1. 使用运行环境中可用的反编译能力处理目标文件
2. 提取方法签名和参数类型定义
3. 还原参数结构

**反编译策略：**
- 仅反编译包含目标接口或参数定义的类
- 优先使用已存在的源码
- 记录反编译来源以便追溯

## 大型项目分批分析建议

### 触发条件

当满足以下任一条件时，启用分批处理：
- 预估接口总数 > 100
- 单个 namespace 接口数 > 30
- 单个 Web Service 方法数 > 20

### 分批处理步骤

**步骤 1：按 namespace/模块分组**
**步骤 2：逐个 namespace 处理**（反编译 → 提取方法 → 生成参数结构 → 验证 → 写入）
**步骤 3：增量写入**（每完成 10 个接口立即写入文件）
**步骤 4：进度检查点**（每个 namespace 完成后验证接口数量）

### 可选分组参考

对于大型项目，按模块子目录 + namespace 拆分文件：
```
route_mapper/
├── {project}_route_mapper_{date}.md                    # 主索引
├── {module}/
│   ├── {project}_module_{module}_{date}.md             # 模块概览
│   └── {project}_{module}_{namespace}_{date}.md        # namespace 详情
└── webservice/
    └── {project}_ws_{service}_{date}.md                # Web Service 详情
```

---

## 覆盖补充建议

发现省略或缺口时，可按当前证据价值补充：

| 检测到的问题 | 自动修正动作 |
|:-------------|:-------------|
| `Action1, Action2等` | 反编译获取完整 Action 列表，替换为全部 |
| `{action}_{method}.action` | 反编译获取实际方法，展开为具体 URL |
| `方法列表: 描述文字` | 反编译获取方法签名，替换为具体方法 |
| `共N个方法` 但列出 < N | 补充缺失的方法直到数量匹配 |
| `interfaceId: xxx ~ yyy` | 展开为逐个 interfaceId |

---

## 故障排除

| 问题 | 解决方案 |
|:-----|:---------|
| 无法识别框架 | 检查项目根目录的配置文件，参考 [FRAMEWORK_PATTERNS.md](references/FRAMEWORK_PATTERNS.md) |
| 路由路径不完整 | 检查类级别的 `@RequestMapping` 和上下文路径配置 |
| 参数类型未知 | 使用反编译工具获取完整的类型定义 |
| 生成的路由信息不完整 | 确认未受安全拦截器/过滤器限制 |
| 模块名不是预期的 | 文件名是动态生成的，根据实际发现的模块/namespace 生成 |
