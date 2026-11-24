---
name: php-thinkphp-audit
metadata:
  tags: [代码审计, php, thinkphp, 框架审计, orm]
description: ThinkPHP 框架特效安全审计工具。针对 ThinkPHP 常见的鉴权/CSRF/模板转义/ORM 写入（Mass Assignment）/调试与配置暴露等机制进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/TPL/XSS/LOGIC/CFG/SESS/SQL 等）。
---

# PHP ThinkPHP 框架安全审计（php-thinkphp-audit）

分析 ThinkPHP 项目源码中的“框架特效安全机制”和典型踩坑模式，重点覆盖：
- 鉴权/权限控制（auth 模块、控制器/中间件 gate）
- CSRF token 机制与跳过路径
- ThinkPHP 模板引擎的自动转义与 raw 输出风险
- ORM/Model 层写入链路导致的 Mass Assignment（`allowField`/场景校验）
- 数据库原生表达式/原始 SQL 注入入口（映射到通用 SQL 类风险）
- debug/异常输出与安全配置开关（映射到 CFG）

## 适用场景

适合已确认是 ThinkPHP 项目，需要结合版本、路由、控制器基类、中间件、ORM 和调试配置判断真实安全影响。

## 不适用场景

依赖名、控制器目录或模板语法只能用于识别框架，不能单独证明漏洞。通用 PHP 风险仍需沿实际请求链确认输入、校验和危险操作。

## 核心判断

ThinkPHP 风险取决于路由到控制器/中间件的绑定、模型字段策略、查询构造方式和生产配置。框架封装可能提供保护，也可能因项目覆盖默认行为而失效。

## 证据标准

- 可确认：框架版本/行为、真实路由、业务校验和危险操作证据闭合，并能观察到越权、写入、注入或信息泄露效果。
- 待验证：发现可疑配置或调用，但路由、中间件、字段策略或最终影响尚未确认。
- 判为否：目标请求未进入危险 action、字段或参数被可靠约束、校验实际生效，或问题只是版本指纹。

## 决策树

- 确认框架版本与入口：关联路由、中间件和控制器基类。
- 检查鉴权：确认登录态、角色和资源归属校验位于真实 action 链路。
- 检查 ORM：追踪整体输入到 `create/save/update`，核对 `allowField` 和敏感字段。
- 检查原生 SQL：区分参数绑定、表达式对象和字符串拼接。
- 检查 debug：确认生产环境响应实际泄露的内容及访问条件。

## 常见误判

- 由 `composer.json` 依赖版本直接推断漏洞可利用。
- 只看到基类中有鉴权方法，未确认目标 action 是否调用。
- 把 `request->param()` 进入模型写入直接等同于敏感字段越权。
- 将模板输出编码问题误判为模板表达式注入。
- 把开发环境 debug 页面当成生产环境信息泄露。

## 框架识别
先确认项目确实是 ThinkPHP，再应用本技能的框架规则：
- 依赖证据：`composer.json` 含 `topthink/think-*` 或 `thinkphp/think-*` 相关依赖
- 入口证据：`public/index.php` 或等价前端入口
- 配置证据：`config/` 目录存在 ThinkPHP 配置文件（如 `app.php`、`database.php`、`middleware.php` 等，按项目实际）
- 运行目录证据：`runtime/` 目录结构（若存在）

## 风险归类
只有形成 finding 时再写明：
- 通用类型码：`AUTH` / `CSRF` / `XSS` / `TPL` / `LOGIC` / `CFG` / `SESS` / `SQL` 等（从你的统一类型码里选）
- 映射原因：为什么落到该类型码（用一句话解释映射逻辑）

## 条件化审计路径
按实际路由、中间件、模型写入和模板输出选择检查点，不要求逐项填表。

### 1) 鉴权与权限控制（AUTH）
按需检查：
- 鉴权入口：控制器中间件/过滤器、基类 Controller/Behavior、路由层权限中间件
- auth 模块使用：是否使用 ThinkPHP 的 auth 相关能力（如 `Auth`/RBAC/角色权限校验函数或等价封装）
- 权限校验的参数来源：资源 ID/用户 ID 来自哪里（路由参数/请求 body/会话），以及是否做归属校验

判定规则：
- 发现“只判断登录态但缺少资源归属/角色细分”则输出 AUTH 风险
- 发现“权限校验在某些分支缺失/异常后绕过”则输出 AUTH 或 LOGIC 风险

### 2) CSRF 防护（CSRF）
按需检查：
- CSRF token 的启用位置：配置项/中间件/表单生成逻辑
- token 的接收字段：来自 body/header 的哪个字段（按项目实际）
- token 校验逻辑：校验函数/中间件入口与失败处理（是否 return/throw 并阻断状态变更）
- 跳过规则：哪些路由、哪些请求方法或哪些场景跳过 CSRF 校验

判定规则：
- 存在跳过规则但覆盖到了状态变更接口 => CSRF 风险
- token 校验失败但仍继续执行业务（例如异常被吞掉）=> CSRF 风险

### 3) 模板引擎转义与 raw 输出（XSS/TPL）
按需检查：
- 模板自动转义策略：模板语法是否默认转义、是否全局关闭
- raw 输出/跳过转义语法：例如模板中存在 `raw`/`|raw` 或等价机制（按项目实际模板引擎版本与用法）
- 用户输入进入模板变量：变量从哪里来（request/session/db），以及是否被直接拼到 HTML/JS/属性上下文

判定规则：
- 若 raw 输出变量可控且未转义 => 映射到 XSS 或 TPL（若涉及表达式/执行链）

### 4) ORM 写入链路（LOGIC：Mass Assignment）
按需检查：
- 输入获取：是否把 `request->param()` / `request->all()` / `$this->request->post()` / 等价结构整体传入模型写入
- 模型写入点：`Model::create/save/update`、`$model->save($data)`、批量赋值行为
- 允许字段策略：是否配置 `allowField`/`field`/场景（scenario）或等价白名单机制

判定规则：
- 输入整体写入且模型缺少敏感字段 deny/allow 约束 => LOGIC 风险
- 存在允许字段白名单但仍包含高风险字段 => LOGIC 风险

### 5) 数据库原生表达式/原始 SQL 风险（SQL）
按需检查：
- 原生 SQL 入口：`Db::query($sql)`、`Db::execute($sql)`、`whereRaw`、`orderRaw`、`buildExpression` 等（按项目实际）
- 用户输入进入原生表达式的证据：拼接、模板替换、字符串拼装点
- 是否存在参数化/绑定策略：`->bind/placeholder/prepare` 等（按项目实际）

判定规则：
- 用户输入进入字符串拼接的原生 SQL 表达式 => SQL 风险

### 6) 安全配置与调试暴露（CFG/SESS）
按需检查：
- debug/异常输出：`app_debug`、`trace`、错误页输出策略、日志级别（按项目实际）
- cookie/session 安全参数：若项目配置文件可见（HttpOnly/Secure/SameSite 等），输出 SESS/CFG 风险映射

判定规则：
- 生产 debug 开启/堆栈回显 => CFG 风险

## 项目写回
- 已检查并排除的 action、中间件或配置写 `project_record_audit(action=cell)`。
- 需要运行时身份、CSRF 或配置条件的假设写 `project_plan_hypotheses`。
- 只有证据闭合后才调用 `project_report_finding`。
- 没有证据的检查项不生成空报告。

