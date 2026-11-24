---
name: php-wordpress-audit
metadata:
  tags: [代码审计, php, wordpress, 框架审计, nonce]
description: WordPress 框架特效安全审计工具。针对 WordPress 常见 nonce/capability/check_admin_referer、AJAX action、escape/sanitize、重定向、安全上传与远程请求等机制进行白盒静态审计，并映射到通用漏洞类型体系（AUTH/CSRF/XSS/SQL/CFG/SSRF 等）。
---

# PHP WordPress 框架安全审计（php-wordpress-audit）

分析 WordPress 项目中的框架特效安全机制，重点覆盖：
- nonce 校验与 capability 权限检查（防止 CSRF 与越权）
- WordPress AJAX 回调（`admin-ajax.php` 的 `wp_ajax_*` 与 `wp_ajax_nopriv_*`）
- 输出 escaping 与模板注入风险（esc_html/esc_attr/esc_url/wp_kses 等）
- `$wpdb` 查询参数化与直接拼接风险
- 重定向（wp_redirect 与 wp_safe_redirect）
- 上传处理（wp_handle_upload）与可执行文件风险
- 远程 HTTP（wp_remote_get/wp_remote_post）与 SSRF 关联

## 适用场景

适合已确认是 WordPress 插件、主题或站点代码，需要结合 hook 注册、AJAX action、nonce、capability、数据源和输出上下文判断安全影响。

## 不适用场景

目录特征和 hook 名称只能用于识别框架入口。nonce 缺失不自动等于越权，capability 存在也不自动等于 CSRF 安全；必须证明动作可达并产生敏感副作用。

## 核心判断

WordPress 安全判断围绕“谁可以进入哪个 action”和“进入后能做什么”：`wp_ajax_nopriv_*` 可能公开暴露动作，nonce 处理请求来源，`current_user_can` 处理权限，输出转义和 `$wpdb->prepare` 分别处理上下文与查询边界。

## 证据标准

- 可确认：hook 注册、请求参数、校验缺口和敏感业务效果证据闭合，并能用真实 action 观察结果。
- 待验证：发现弱校验或危险调用，但 action 未注册、回调不可达、字段不受控或副作用不明确。
- 判为否：能力与 nonce 校验均覆盖、查询或输出上下文安全，或动作只读且没有安全影响。

## 决策树

- 找到 hook/action：确认注册名、登录态范围和真实回调。
- 检查状态变更：区分 nonce、capability 和对象归属三种校验。
- 检查输出与查询：按 HTML/属性/URL/SQL 上下文判断转义和参数化。
- 检查上传与远程请求：追踪类型、目录、URL 和重定向边界。
- 只有 hook 或危险函数命中：保留为信号，不直接生成已确认漏洞。

## 常见误判

- 把 nonce 当作能力授权，或把登录态当作 CSRF 防护。
- 只看 `wp_ajax_*`，忽略 `wp_ajax_nopriv_*` 和真实 action 名称。
- 使用 `$wpdb->prepare` 就认定安全，未检查占位符和拼接位置。
- 看到 `wp_safe_redirect` 或 escaping 函数就忽略上下文差异。
- 在验证 CSRF 或权限缺失时执行批量删除、配置修改等副作用。

## 框架识别
先用项目内证据确认 WordPress 形态，避免把普通 PHP 项目误套 WordPress 规则：
- 目录特征：`wp-content/`、`wp-admin/`、`wp-includes/`
- 核心文件：`wp-config.php` 或 `wp-settings.php`
- 插件/主题目录：`wp-content/plugins/`、`wp-content/themes/`

## 审计方法
从真实注册入口开始，不要机械扫描文件名或逐个函数填表。

1. 找到 hook 或 AJAX action 的注册位置，确认回调函数和触发条件。
2. 判断登录态、nonce、capability 和对象归属是否覆盖真实敏感副作用。
3. 追踪请求数据或配置值到具体 Sink，检查分支、过滤和落点。
4. 只有“入口可达 + 参数可控 + 校验缺口 + 敏感效果”形成证据链时，才升级为漏洞。
5. 单个 action 没有安全影响时记录排除理由，不继续重复分析同一路径。

## 条件化检查点
按项目实际出现的入口选择检查，不要求逐项生成内容。

- AJAX：区分 `wp_ajax_*` 与 `wp_ajax_nopriv_*`，确认真实 action 名和回调。
- nonce：检查 `wp_nonce_field`、`check_admin_referer`、`wp_verify_nonce`、`check_ajax_referer` 的生成与校验是否位于同一动作。
- 权限：检查 `current_user_can`、`user_can`、`is_user_logged_in`，并区分登录、能力授权和对象归属。
- 输出：检查用户输入进入 `echo/print`、属性、URL、HTML 上下文时的 escaping；`wp_kses` 需结合允许标签判断。
- SQL：检查 `$wpdb->prepare` 的占位符数量、拼接位置和查询类型；存在 prepare 不代表整条 SQL 安全。
- 文件：检查 `wp_handle_upload`、`media_handle_upload`、目录、扩展名、MIME、访问控制和后续执行。
- 重定向：检查 `wp_redirect` 与 `wp_safe_redirect` 的目的地来源和 host/scheme 校验。
- 远程请求：检查 `wp_remote_get/wp_remote_post` 的 URL 来源、协议限制和内网边界。
- 短代码、REST、Cron、CLI 和主题模板同样可以作为入口，不要只检查 AJAX。

## 风险归类
只有形成 finding 时才需要写通用类型码，例如 `AUTH`、`CSRF`、`XSS`、`SQL`、`UPLOAD`、`SSRF`、`REDIR`。

写回时说明具体入口、guard、Sink 和影响，不要为了覆盖所有类型码制造空结论。

## 项目写回
- 已检查并排除的 action 或路径写 `project_record_audit(action=cell)`。
- 需要动态用户、nonce 或配置条件才能成立的方向写 `project_plan_hypotheses`。
- 证据闭合后按统一规范调用 `project_report_finding`。
- 没有证据的检查项不生成独立报告，也不创建空文件。

