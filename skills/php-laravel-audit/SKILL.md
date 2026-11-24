---
name: php-laravel-audit
metadata:
  tags: [代码审计, php, laravel, 框架审计, blade]
description: Laravel 框架特效安全审计工具。针对 Laravel 常见鉴权/CSRF/Session/模型填充/Blade 渲染等框架特性进行白盒静态审计，并将风险映射到你现有通用漏洞类型体系（AUTH/CSRF/LOGIC/XSS/CFG 等）。
---

# PHP Laravel 框架安全审计（php-laravel-audit）

分析 Laravel 项目源码中的“框架特效安全机制”和“常见踩坑模式”，重点覆盖：
- 鉴权与路由保护（middleware/auth/Policies/Gates）
- CSRF 与 token 保护（VerifyCsrfToken、except 列表、API 与 Cookie 认证差异）
- Session 与 Cookie 安全（session_regenerate_id、cookie flags、remember 机制的风险点）
- Eloquent mass assignment 与 request-to-model 写入缺陷（Model::create/fill/update 与 `$request->all()` 链）
- Blade 模板渲染中的 raw 输出与表达式执行风险（`{!! !!}`、`@php` 以及未转义输出）
- Laravel signed URL 与路由签名校验是否闭环（Signed middleware 与生成位置）

## 适用场景

适合已确认是 Laravel 项目，需要结合框架版本、路由中间件、认证策略、配置和具体 handler 判断安全影响。

## 不适用场景

只看到 `composer.json`、`artisan` 或 Laravel 目录结构不代表存在漏洞。通用 PHP 问题也不能仅因框架封装就改变可利用性，必须回到实际版本、配置和请求链。

## 核心判断

Laravel 风险来自框架机制与项目配置的交互：路由是否进入正确 middleware group、异常路径是否绕过授权、mass assignment 是否暴露敏感字段、模板是否跳过转义，以及签名或 CSRF 校验是否真正执行。

## 证据标准

- 可确认：框架版本或行为、真实路由、配置/中间件和受影响 handler 的证据闭合，并能观察到越权、写入或脚本执行等效果。
- 待验证：发现危险配置或调用，但路由可达性、middleware 生效范围或实际影响尚未确认。
- 判为否：框架版本不受影响、路由未进入危险 handler、校验实际生效，或问题只有静态代码坏味道。

## 决策树

- 确认框架与版本：判断候选问题是否受版本差异影响。
- 梳理 route group：核对 middleware、prefix、guard 和 except 的实际覆盖。
- 找到危险 handler：追踪输入、授权、模型写入或模板输出。
- 配置存在但未达危险路径：降低结论并补齐路由证据。
- 形成真实请求效果：输出最小 PoC 和框架层面的修复边界。

## 常见误判

- 由目录结构推断框架版本或安全状态。
- 只看路由文件中有 `auth`，忽略 group、except 和控制器覆盖。
- 把 `$request->all()` 与可写敏感字段同时出现直接认定为越权。
- 将 Blade `{!! !!}` 命中等同于 XSS，忽略输入来源和转义。
- 忽略 API guard、Cookie 会话和 CSRF middleware 的作用范围差异。

## 框架识别
先确认项目确实是 Laravel，再应用本技能的框架规则：
- `composer.json` 依赖
- 典型目录：`app/`、`routes/`、`config/`
- 核心入口：`public/index.php`、`bootstrap/app.php`

## 风险归类
只有形成 finding 时再写明：
- 适用的通用类型码：`AUTH` / `CSRF` / `LOGIC` / `XSS` / `CFG` / `SESS` / `FILE` 等（从你的 `shared/SEVERITY_RATING.md` 可用类型码中选）
- 这条 Laravel 风险为什么落到该通用类型码（用一句话解释映射逻辑）

## 条件化审计路径
按真实路由、middleware 和数据流选择检查点，不要求逐项填表。

### 1) 鉴权与权限保护（AUTH）
优先检查以下证据：
- 受保护路由进入点：`routes/web.php` 与 `routes/api.php` 中的 `middleware('auth')` / `middleware('can')` / `Route::middleware([{value}])->group({value})`
- 权限逻辑：`Gate::` / `Policy` / `authorize` / `can` / `->can({value})` 的位置证据
- 风险判断：是否存在“已登录但无资源级归属校验”的模式（例如只判断 user 存在，不判断 owner）
- 路由命名与资源绑定：是否存在 Route Model Binding 但未做归属校验

判断要求：
- 若发现缺失：必须给出“缺失位置 + 可能被绕过的请求类型（GET/POST/API）+ 修复建议”
- 若已完成明确扫描范围且未发现：记录否定证据（例如 except/guard 为空、敏感路由均有 middleware 等），不为未触发路由制造空结论

### 2) CSRF 与 token 保护（CSRF）
按需检查：
- CSRF middleware：`VerifyCsrfToken` 或等价中间件
- except 列表：哪些路由被排除
- API 与 Cookie 认证差异：若项目对 API 使用 Cookie/session，需要确认 API 路由是否仍受 CSRF 保护

判断要求：
- 必须覆盖“可能绕过分支”：例如仅部分方法不校验、仅某些 Content-Type 不校验、仅在 AJAX 时跳过等

### 3) Session 与 Cookie 安全（SESS）
按需检查：
- 登录后会话固定防护：是否存在 `session_regenerate_id` 或 Laravel 对应机制证据
- Cookie flags：`HttpOnly`/`Secure`/`SameSite` 的配置位置（`config/session.php` 或自定义中间件）
- logout：退出是否清理 session

### 4) Eloquent mass assignment（LOGIC）
优先检查数据流链：
- request 输入获取：`$request->all()`、`$request->input({value})`、`json_decode({value})`
- 写入模型点：`Model::create({value})` / `Model::update({value})` / `$model->fill({value})` / `->save()`
- 模型填充策略：`$fillable` / `$guarded` 的配置位置

判定规则：
- `$request->all()` 或等价输入直接进入 `create/fill/update`，且模型缺少针对敏感字段的 denylist（或 `$fillable` 过宽），则输出风险

### 5) Blade raw 输出（XSS）
按需检查：
- raw 输出：`{!! {value} !!}`、`@php` 以及任何“跳过转义”的指令或回调
- 用户输入来源：来自 `$request`、`request()`、数据库字段回填但未转义时的证据

判定规则：
- 若 raw 输出内容存在用户可控字段，且未做 `e()` 或等价 escape，则输出风险映射到 `XSS` 或相关模板注入风险（若你项目用到模板表达式执行则映射到 `TPL`）

### 6) Signed URLs 与签名校验闭环（AUTH 或 CFG）
按需检查：
- 签名 URL 生成：`URL::temporarySignedRoute` / `URL::signedRoute`
- 验证中间件：`middleware('signed')` 或等价校验机制

判定规则：
- 若仅生成但无签名验证中间件，或验证逻辑可被绕过，输出风险映射到 `AUTH` 或 `CFG`

## 项目写回
- 已检查并排除的路由或组件写 `project_record_audit(action=cell)`。
- 需要运行时用户或配置条件的假设写 `project_plan_hypotheses`。
- 只有证据闭合后才调用 `project_report_finding`。
- 没有证据的检查项不生成空报告。

