---
name: php-open-redirect-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 开放重定向, url校验]
---

# PHP 开放重定向审计（php-open-redirect-audit）

分析 PHP 项目源码中，所有“跳转/重定向”行为是否可能被用户控制目的地址，导致钓鱼或 OAuth 等流程被劫持。

## 适用场景

适合登录、登出、支付回跳、OAuth、短链或通用 `next/return_url` 参数进入 Location 的流程，需要判断最终目的地是否可被浏览器解释为外部站点。

## 不适用场景

所有重定向都不等同于开放重定向。目标固定、只允许站内相对路径、最终仍受同源约束，或危险输入在规范化后已被拒绝时，应判为否。

## 核心判断

关键是用户输入经过服务器和浏览器解释后，最终导航目标是否成为攻击者控制的外部 scheme 或 authority。只检查字符串中是否包含 `http` 不足以判断，必须考虑解码、协议相对 URL、反斜杠和浏览器归一化。

## 证据标准

- 可确认：真实路由、用户可控目的地、最终响应 Location 和外部导航效果形成闭环。
- 待验证：存在目的地映射和弱校验，但最终响应值、浏览器解释或受影响流程尚不明确。
- 判为否：目的地固定、被可靠限制为站内相对路径、危险 scheme/authority 被拒绝，或响应不能触发导航。

## 决策树

- 找到跳转输出点：回查目的地来源和校验位置。
- 存在 allowlist：确认比较发生在规范化之后，且覆盖 scheme、host、端口和路径。
- 使用相对路径策略：检查 `//`、反斜杠、编码和控制字符的最终解释。
- 响应只跳到同源页面：降低影响，继续检查是否可影响 OAuth 或凭据流程。
- 可导航到外部站点：输出真实请求和浏览器观察点。

## 常见误判

- 只看到可控参数就认定开放重定向。
- 将 URL 编码、字符串前缀检查或域名包含判断视为可靠 allowlist。
- 忽略浏览器对反斜杠和多余斜杠的归一化差异。
- 把普通站内跳转或固定登录后跳转列为漏洞。
- 未检查 OAuth state、回调绑定和用户交互就扩大影响。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-REDIR-{序号}`

## 必检 Sink（可选）识别以下跳转输出点：
- `header("Location: {value}")`
- `<meta http-equiv="refresh" content="{value}">`
- `redirect()` / `to()` / `return redirect({value})`
- 自定义跳转函数（内部最终调用 Location 输出）

## 可控性追踪（按需）必须追踪以下两类变量：
1. 目的地来源：通常来自 `$_GET['next']`/`$_POST['url']`/`Referer`/`return_to`
2. 目的地校验：是否只允许相对路径、是否 allowlist、是否拒绝 scheme（`http://`/`//`）、是否校验域名

## 绕过条件（按需）必须识别并输出潜在绕过：
- scheme 绕过：`//evil.com`、`http:%2f%2fevil.com`
- 编码绕过：双重编码、URL 编码的冒号/斜杠
- 尾部/空白字符绕过（旧实现常见）

## 条目记录建议
- 位置证据：跳转函数位置 + 路由
- 数据流链：用户输入 -> 校验 -> header/redirect
- 可利用前置条件：通常需登录（若在登录后跳转）与攻击者能否控制参数
- 验证 PoC（可按需补充真实路由；把目的地参数替换为真实字段名）
- 修复建议：只允许相对路径 + 服务器端 allowlist + 对编码/scheme 做归一化后校验

## 证据引用（有 trace 时）
每条开放重定向疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **REDIR 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_REDIR_OUTPUT_POINT`：跳转输出点位置证据（header/redirect 的最终输出位置）
2. `EVID_REDIR_DEST_SOURCE_MAPPING`：目的地来源变量映射证据（从路由参数到目的地变量）
3. `EVID_REDIR_DEST_VALIDATION_NORMALIZATION`：目的地校验/归一化/allowlist/refuse scheme 的分支证据（含编码绕过处理分支）

## tracer 证据使用说明

