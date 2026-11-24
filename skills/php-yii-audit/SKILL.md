---
name: php-yii-audit
metadata:
  tags: [代码审计, php, yii, 框架审计, rbac]
description: Yii 框架特效安全审计工具。针对 Yii（通常指 Yii2）访问控制（AccessControl/RBAC）、CSRF、输入过滤规则、输出编码策略、URL/重定向安全等进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/XSS/CFG/LOGIC 等）。
---

# PHP Yii（Yii2）框架安全审计（php-yii-audit）

分析 Yii2 项目的框架机制与配置踩坑，重点覆盖：
- 访问控制：`AccessControl` filter、`roles` 规则、matchCallback 的使用
- RBAC：`user->can`/`can()` 路径的鉴权完整性
- CSRF：`enableCsrfValidation` 与 cookie validation
- 输出编码：views 是否使用 `Html::encode`、`HtmlPurifier`，以及危险的原样输出
- URL 与跳转：redirect/Url 生成是否受信任输入控制
- 入参过滤：`rules()`、`safeAttributes()`、场景（scenario）是否导致 Mass Assignment

## 适用场景

适合已确认是 Yii2 项目，需要结合 controller behaviors、AccessControl、RBAC、模型 rules/scenarios 和真实 action 判断安全影响。

## 不适用场景

看到 Yii 目录、`AccessControl` 或 `load()` 不代表漏洞。必须继续证明 action 可达、规则覆盖关系和安全效果；通用输出或 SQL 问题仍需回到具体上下文。

## 核心判断

Yii 风险通常来自框架配置与项目覆盖的交互：AccessControl 规则顺序与 action 覆盖、RBAC 检查粒度、对象归属、CSRF 开关，以及模型安全字段和场景是否允许敏感数据进入。

## 证据标准

- 可确认：框架配置、真实 controller/action、校验缺口和敏感业务效果证据闭合。
- 待验证：发现过宽规则或危险调用，但 behavior 未命中、action 不可达、字段未实际写入或影响不明确。
- 判为否：规则和对象归属校验覆盖目标 action、CSRF 生效、模型字段受约束，或代码没有安全敏感副作用。

## 决策树

- 找到 controller/action：确认路由和 behaviors 生效范围。
- 检查 AccessControl：按规则顺序、roles 和 actions 判断是否覆盖。
- 检查对象操作：确认 RBAC 之后是否还有 owner/tenant 归属校验。
- 检查模型写入：追踪 `load()` 输入、safeAttributes、scenario 和最终保存字段。
- 只有 filter 名称或模型写法命中：保留候选，不直接确认越权。

## 常见误判

- 只看到 `AccessControl` 就认为所有 action 都已保护。
- 将 `user->can()` 当成对象归属校验。
- 把 `load()` 直接等同于 Mass Assignment，忽略 safe attributes 和 scenario。
- 忽略 CSRF 在 GET、API 或无状态场景中的适用差异。
- 用真实业务对象执行删除、审批或角色变更来验证越权。

## 框架识别
先确认项目确实是 Yii，再应用本技能的框架规则：
- 依赖证据：`composer.json` 包含 `yiisoft/yii2` 或相关组件
- 入口证据：`web/index.php` 或 `yii` 入口脚本
- 应用目录：`controllers/`、`models/`、`views/`

## 风险归类
只有形成 finding 时再写明：
- 通用类型码：`AUTH` / `CSRF` / `XSS` / `CFG` / `LOGIC` 等
- 映射原因

## 条件化审计路径
按实际 controller/action、AccessControl 和对象归属选择检查点，不要求逐项填表。

### 1) AccessControl 鉴权规则正确性（AUTH）
按需检查：
- `behaviors()` 中的 `AccessControl` 配置：`rules`、`roles`、`matchCallback` 与 action 覆盖范围
- 是否存在只依赖 matchCallback 的宽松模式
- 是否有自定义认证逻辑但未落到统一 filter

判定规则：
- 有路径能绕过 AccessControl 或 rules 过宽，则输出 AUTH 风险

### 2) RBAC/权限校验完整性（AUTH/LOGIC）
按需检查：
- 控制器/服务层的 `user->can({value})`、`can()` 或等价权限判断
- 对象归属校验：是否同时验证 owner_id/user_id 或资源的归属关系

判定规则：
- 若仅判断“用户有权限类型”，但未校验对象归属，输出 AUTH 或 LOGIC 风险

### 3) CSRF（CSRF）
按需检查：
- `enableCsrfValidation` 与 cookie validation 设置
- token 接收字段与验证失败处理方式（是否早退）

### 4) 输出编码与 XSS（XSS）
按需检查：
- views 中是否存在原样输出：`Html::encode` 被绕过的情况、或使用 `raw` 类机制
- 模板中是否将用户输入直接拼接到 HTML 属性/JS/URL 中

### 5) 输入过滤与 Mass Assignment（LOGIC）
按需检查：
- 模型 `rules()`、`safeAttributes()`、`scenarios()` 的配置
- 是否存在 `load($request->post())` 后直接保存，而敏感字段未被禁止

## 项目写回
- 已检查并排除的 controller、action 或 filter 写 `project_record_audit(action=cell)`。
- 需要运行时用户、场景或 CSRF 条件的假设写 `project_plan_hypotheses`。
- 只有证据闭合后才调用 `project_report_finding`。
- 没有证据的检查项不生成空报告。

