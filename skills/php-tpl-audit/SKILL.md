---
name: php-tpl-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 模板注入, ssti, rce]
---

# PHP 模板注入/SSTI 审计（php-tpl-audit）

分析 PHP 项目源码，识别模板注入（SSTI）与危险表达式执行风险：用户可控内容影响模板选择、渲染表达式解析或转为可执行代码。

## 适用场景

适合模板名、模板片段或表达式字符串来自请求或可写数据源，并进入模板引擎加载、编译或求值流程的场景。

## 不适用场景

把用户数据传入固定模板不等于模板注入；`|raw`、`{!! !!}` 或关闭自动转义通常首先属于输出编码问题。只有模板语法或表达式控制进入可执行解析链时，才需要评估 SSTI。

## 核心判断

需要区分“模板数据可控”和“模板控制面可控”。SSTI 的成立依赖攻击者能改变模板名、模板源码或表达式，并让引擎编译或求值这些内容；沙箱、缓存和固定模板映射会直接影响可利用性。

## 证据标准

- 可确认：模板或表达式控制证据、引擎解析/求值入口和执行结果证据闭合，并能观察到模板表达式产生的实际效果。
- 待验证：存在模板名或表达式映射，但沙箱、缓存、版本、编译分支或执行结果尚未确认。
- 判为否：输入只作为模板变量、模板名来自固定 allowlist、表达式未被求值，或输出问题只能形成 XSS。

## 决策树

- 找到渲染入口：区分模板名、模板字符串和渲染变量的来源。
- 数据可控：优先检查输出上下文和 XSS，不直接升级为 SSTI。
- 模板名可控：检查是否存在固定映射、后缀约束和目录限制。
- 模板片段/表达式可控：确认引擎是否编译、缓存和求值，以及沙箱能力。
- 只有错误回显：继续验证是否包含表达式求值结果。

## 常见误判

- 用户输入进入模板变量就认定模板注入。
- 把 Blade `{!! !!}` 或 Twig `|raw` 等同于 SSTI。
- 只控制模板文件名但受固定目录和扩展名约束时仍按 RCE 处理。
- 忽略模板缓存导致写入的模板内容未立即生效。
- 使用会破坏模板目录或业务配置的 payload 做验证。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-TPL-{序号}`

## TPL Sink（按需）模板相关渲染/执行点：
- Twig：
  - `Environment->load($templateName)` / `createTemplate($name)` / `render($template)`
  - `|raw` 或关闭自动转义策略（必须有证据点）
- Laravel Blade（Illuminate/View，PHP 原生常见）：
  - `view($templateName, $data)` / `View::make($templateName, $data)`
  - `Illuminate\View\Factory->make($template)` / 渲染入口 `$engine->render({value})`
  - 当模板可控时：Blade raw 输出（`{!! !!}`）与 `@php` 指令属于高危执行链（必须用证据点落到渲染/编译入口）
- Smarty：
  - `Smarty->fetch($template)` / `display($template)`
- 自定义模板引擎：
  - `eval()`、`preg_replace('/e')`、`create_function` 等被用于模板表达式
  - `call_user_func` / `call_user_func_array` 参数来自用户输入（可能触发表达式）

## 可控性（按需）形成结论时说明：
- 用户输入如何进入“模板名/模板片段/表达式字符串”
- 是否存在严格的白名单模板名映射
- 是否存在沙箱/表达式限制

## tracer 使用条件

## 证据引用（有 trace 时）
每条模板注入/SSTI 疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **TPL 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_TPL_ENGINE_RENDER_OR_PARSE_ENTRY`：模板引擎渲染/表达式解析点位置证据（load/createTemplate/fetch/render 或等价入口）
2. `EVID_TPL_TEMPLATE_OR_EXPR_CONTROL`：模板名或表达式是否可控证据（来自路由参数到模板构造变量的映射）
3. `EVID_TPL_EXEC_CHAIN_ENTRY`：执行链入口证据（表达式求值/编译/执行：如 raw/disable escape、eval/use of call_user_func 等）

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。

条目必须包含：数据流链、可利用前置条件、可执行 PoC 框架、修复建议与搜索语句。

