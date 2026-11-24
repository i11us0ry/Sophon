---
name: php-crlf-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, crlf, 响应头, 注入]
---

# PHP CRLF 响应分割审计（php-crlf-audit）

分析 PHP 项目源码，识别用户可控数据是否进入响应头（header）、Cookie、或其他可被浏览器/中间件解释为新头，从而造成响应拆分、缓存投毒或重定向劫持。

## 适用场景

适合用户输入进入 `header`、`setcookie`、重定向或其他响应头输出点，需要判断控制字符过滤和实际响应影响。

## 不适用场景

只有 header 函数命中时，不能直接认定 CRLF。必须证明输入可控、控制字符未被阻断并形成新头或响应变化。

## 核心判断

CRLF 风险取决于用户输入是否进入 header/cookie 值、`\r\n` 是否被拒绝或编码、最终响应是否被浏览器或中间件拆分解释。

## 证据标准

- 输出点、输入来源和过滤/编码位置。
- 控制字符是否实际进入最终响应。
- 响应头变化、重定向或缓存影响证据。
- 缺失 EVID 时标记待验证。

## 决策树

- 输入进入 header：检查换行和控制字符处理。
- 过滤存在：判断是否完全拒绝、替换或仅部分编码。
- 真实请求可控：验证最小 payload 和响应变化。
- 无新头或行为变化：不升级。
- 影响缓存或重定向：扩大影响评估。

## 常见误判

- 只看到 header 函数就认定漏洞。
- 把 URL 编码当成服务端解码后的安全处理。
- 只看 302，不看注入头。
- 忽略中间件和代理对 header 的规范化。
- 用危险缓存投毒验证生产流量。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-CRLF-{序号}`

## 必检 Sink（可选）识别以下点：
- `header()` 的 header 值参数含用户输入
- `setcookie()` 的 cookie name/value/domain/path 中含用户输入
- 输出到自定义 header 的函数/封装（最终仍调用 header）
- 返回 body 内拼接到 HTTP 响应头（少见，但仍需在代码中证据化）

## 必检过滤与归一化（可选）形成结论时说明：
- 是否对 `\r`、`\n` 做了拒绝或清洗
- 是否对可见控制字符进行了处理
- 是否进行了 URL 编码/转义（但注意：错误的“部分过滤”可能绕过）

## PoC（可选）- 可给出真实路由与可控字段名
- payload 必须体现 CRLF：`%0d%0a`（或 `\r\n`）并说明预期效果（如注入 Location 或自定义 header）

## 条目记录建议

## 证据引用（有 trace 时）
每条 CRLF/响应分割疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **CRLF 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_CRLF_OUTPUT_POINT`：响应头/ Cookie 输出点位置证据（header/setcookie 等最终输出位置）
2. `EVID_CRLF_USER_INPUT_INTO_HEADER_COOKIE`：用户输入进入 header/cookie 值的证据（包含控制字符进入点）
3. `EVID_CRLF_CONTROL_CHAR_FILTERING_ENCODING`：`\r\n` 或控制字符过滤/编码证据（拒绝/清洗/编码实现的对应片段）

## tracer 证据使用说明

