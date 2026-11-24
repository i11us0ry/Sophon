---
name: php-symfony-audit
metadata:
  tags: [代码审计, php, symfony, 框架审计, twig]
description: Symfony 框架特效安全审计工具。针对 Symfony 常见 security.yaml、CSRF、Twig/Twig raw、表达式与访问控制等框架机制做白盒静态审计，并将风险映射到通用漏洞类型体系（AUTH/CSRF/CFG/XSS/TPL/LOGIC 等）。
---

# PHP Symfony 框架安全审计（php-symfony-audit）

分析 Symfony 项目源码中的“框架特效安全机制”和“配置/用法踩坑”，重点覆盖：
- `config/packages/security*.yaml` 的 access_control、firewalls 配置正确性
- CSRF 防护机制（表单提交与 token 验证）
- Twig 渲染自动转义与 raw 输出风险
- Symfony 访问表达式与安全拦截链（map 到 AUTH/EXPR/TPL 视情况）
- HttpClient 外联策略（SSRF 类风险以通用 SSRF 类型映射）

## 适用场景

适合已确认是 Symfony 项目，需要结合安全配置、路由、事件监听器、控制器和模板判断实际访问控制与输入影响。

## 不适用场景

存在 `security.yaml`、`Twig` 或 `HttpClient` 不代表配置错误。只命中组件、模板语法或安全表达式时，必须继续证明路由可达性和安全效果。

## 核心判断

Symfony 安全结论依赖配置生效顺序与运行时匹配：`access_control` 的首个匹配规则、firewall 身份状态、路由默认条件、CSRF token 验证和 Twig 转义上下文共同决定真实行为。

## 证据标准

- 可确认：框架版本/配置、真实路由、安全匹配结果和受影响 handler 证据闭合，并能观察到越权、请求伪造、注入或外联效果。
- 待验证：发现危险配置或调用，但匹配顺序、路由覆盖、身份状态或最终影响尚不明确。
- 判为否：规则实际覆盖目标路径、校验执行成功、模板上下文安全，或代码不可由请求入口触发。

## 决策树

- 识别 firewall：确认目标是匿名、认证还是无状态区域。
- 核对 access_control：按顺序找到首个匹配规则，再映射到真实路由。
- 检查 CSRF 与表单：确认 token 创建、提交字段和失败阻断路径。
- 检查 Twig/EXPR：区分数据输出、模板控制、表达式输入和自动转义上下文。
- 检查 HttpClient：追踪 URL 来源、重定向和 allowlist，不要只按组件定级。

## 常见误判

- 把 `access_control` 中任意 deny 规则当成一定会覆盖后续路由。
- 忽略 firewall、路由 locale/prefix 和请求方法对匹配的影响。
- 看到 Twig `|raw` 就认定 SSTI，未证明模板语法可控。
- 把安全表达式名称可控等同于表达式字符串可控。
- 将普通 Symfony 错误页或 debug 信息指纹直接当成高危漏洞。

## 框架识别
先确认项目确实是 Symfony，再应用本技能的框架规则：
- 典型目录：`config/`、`src/`、`templates/`
- 依赖证据：`composer.json` 中 `symfony/framework-bundle` 等
- 入口证据：`public/index.php` 或类似前端控制器

## 风险归类
只有形成 finding 时再写明：
- 适用的通用类型码：`AUTH` / `CSRF` / `CFG` / `XSS` / `TPL` / `LOGIC` / `SESS` / `SSRF` / `EXPR` 等
- 映射原因：为什么该 Symfony 风险会落在该类型码（用一句话）

## 条件化审计路径
按 firewall、access_control、路由和数据流选择检查点，不要求逐项填表。

### 1) 访问控制与鉴权策略（AUTH）
按需检查：
- `security.yaml` 中的 `access_control` 规则
- `firewalls` 配置（是否 `anonymous: true`、是否 `stateless: true` 与认证方式）
- `switch_user`、`role_hierarchy` 或 voter/policy 类配置（如存在）

判定规则：
- 若存在过宽允许（例如过于泛化的匿名规则覆盖敏感路径），输出 AUTH 风险
- 若存在“有认证但缺少角色/归属校验”的模式，输出 AUTH 或 LOGIC 风险

### 2) CSRF 防护（CSRF）
按需检查：
- Symfony CSRF 相关配置（`framework: csrf_protection` 或组件级配置）
- 表单类型使用中 CSRF token 的生成与接收方式
- token 验证失败的处理路径（是否早退、是否仅在某些分支校验）

判定规则：
- 若存在“某些路由/表单禁用了 CSRF 或 CSRF token 接收字段不一致”，输出 CSRF 风险

### 3) Twig 自动转义与 raw 输出（XSS/TPL）
按需检查：
- Twig 配置：自动转义是否被关闭（全局或局部）
- 模板中 raw 输出点：`|raw`、`{% autoescape false %}`、以及任何“绕过转义”的指令
- 数据来源：raw 输出的变量来自哪里（request/session/数据库字段）

判定规则：
- raw 输出变量来源可控且未做 escape，则映射到 XSS 或 TPL（若存在表达式执行/模板引擎可控）

### 4) 安全表达式与求值风险（EXPR/TPL/AUTH）
按需检查：
- ExpressionLanguage 用于 security 的位置（voter/policy 中 `is_granted` 或表达式条件）
- 表达式字符串来源是否可能被用户控制（例如表达式拼接）

判定规则：
- 若表达式字符串可控，按 EXPR 或 TPL 风险输出

### 5) 外联 HTTP 与内网访问（SSRF）
按需检查（仅做框架关联检查）：
- `HttpClient`/`KernelInterface` 等外联调用的封装入口
- URL/host 是否来源于用户输入，是否存在 allowlist 或内网拦截

## 项目写回
- 已检查并排除的 firewall、路由或组件写 `project_record_audit(action=cell)`。
- 需要运行时身份或配置条件的假设写 `project_plan_hypotheses`。
- 只有证据闭合后才调用 `project_report_finding`。
- 没有证据的检查项不生成空报告。

