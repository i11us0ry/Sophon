---
name: php-ldap-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, ldap注入, 目录服务]
---

# PHP LDAP 注入审计（php-ldap-audit）

分析 PHP 项目源码，识别 LDAP 查询相关代码（filter/DN 构造），检测 LDAP 注入风险：攻击者可通过控制 filter 或 DN 片段改变 LDAP 查询语义，从而导致未授权查询、数据泄露或认证绕过。

## 适用场景

适合用户输入进入 LDAP filter、DN 或项目封装的目录查询参数，需要判断输入是否改变查询语法以及最终 `ldap_*` 调用是否可达。

## 不适用场景

只发现 LDAP 扩展、连接配置或登录表单时不能直接判定注入。必须证明用户输入进入 filter/DN 片段并被 LDAP 查询执行点使用。

## 核心判断

需要区分可控参数值与可控 LDAP 语法片段。重点检查 filter 与 DN 是否分别使用正确的上下文转义，属性名和连接对象是否受控，以及转义后的值是否确实进入最终查询。

## 证据标准

- 可确认：LDAP 执行点、filter/DN 字符串构造和用户输入映射证据闭合，并能观察到查询结果或认证行为改变。
- 待验证：存在拼接和可控输入，但转义模式、查询上下文或最终执行点尚不明确。
- 判为否：输入仅作为固定模板值且经过上下文正确的转义，或数据未进入实际 LDAP 查询。

## 决策树

- 找到 `ldap_search/read/list`：回查 filter、base DN 和项目封装的最终传参。
- 用户输入进入字符串构造：判断是属性名、匹配值、逻辑连接符还是完整 filter。
- 使用 `ldap_escape`：核对 filter/DN 模式、ignore 参数和是否在拼接前覆盖所有用户输入。
- 响应存在差异：用基线与对照确认变化来自查询语义，而不是目录状态或错误处理。
- 证据不足：保留候选并说明缺失的 EVID，不输出已确认结论。

## 常见误判

- 使用 `ldap_escape` 就认定安全，未核对 filter/DN 上下文。
- 只转义匹配值，却允许用户控制属性名、逻辑操作符或完整 filter。
- 将 LDAP 连接失败、空结果或登录失败直接视为注入成功。
- 忽略项目封装、默认 filter 和额外条件对输入的影响。
- 用批量修改或删除目录对象的请求做验证。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-LDAP-{序号}`

## LDAP Sink（按需）识别以下函数/语句作为最终执行点：
- `ldap_search({value})` / `ldap_read({value})` / `ldap_list({value})`
- 以及它们的项目封装（只要最终还是传入 filter/DN 字符串）

## 必检证据点（按需）每条 LDAP 疑似漏洞有对应 trace 时优先引用 `php-route-tracer` trace 中 `## 9) Sink Evidence Type Checklist` 的 **LDAP 行**对应证据点 ID：
1. `EVID_LDAP_EXEC_POINT`：LDAP 查询执行点（ldap_* 函数调用/封装最终传参处）证据
2. `EVID_LDAP_FILTER_STRING_CONSTRUCTION`：LDAP filter/DN 字符串构造位置（拼接/模板化）证据
3. `EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`：用户可控参数到 filter/DN 片段的映射证据

## 可控性与注入点确认（按需）按需判断：
- 用户输入从哪里来：`$_GET/$_POST/json/php://input/$_COOKIE/$_FILES` 或其衍生字段
- filter/DN 是如何构造：是否直接字符串拼接、是否经过转义、是否存在 allowlist 白名单
- 注入可改变的语义点：例如可否注入 `*`、`(`、`)` 等 LDAP filter 语法相关字符（或通过编码绕过转义）
- 是否存在转义/净化：优先使用 `ldap_escape`（或自定义等价函数），且必须能证明用于最终 filter/DN 构造

## tracer 使用条件
- filter/DN 由多个变量/函数层级拼接或经过 JSON 解码后拼接
- filter/DN 进入 `ldap_search/read/list` 之前存在分支（if/switch/try）或提前 return/throw
- 转义逻辑存在条件分支（某些分支没转义、或仅转义部分字段）

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。
```

## 漏洞记录建议
```markdown
### [{等级前缀}-LDAP-{序号}] LDAP 注入漏洞（filter/DN 拼接导致查询语义被改变）

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function}) |

#### 数据流链（Source → Sink）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}
- 转义/白名单可靠性：{已可靠防护/防护缺失/防护可绕过}

#### 证据引用（可参考 php-route-tracer）
- `EVID_LDAP_EXEC_POINT`：{对应证据要点简述}
- `EVID_LDAP_FILTER_STRING_CONSTRUCTION`：{对应证据要点简述}
- `EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT`：{对应证据要点简述}

#### 验证 PoC（按需：给出可执行请求）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Cookie/Auth}

{Payload}
```

PoC 生成策略（必须写清楚）：
- 先用“探测 payload”证明 filter/DN 被求值（返回数量/状态码/响应差异）
- 再用“注入 payload”证明可改变查询语义（如扩大匹配范围/绕过条件）

#### 建议修复
- 使用 `ldap_escape($value, '', LDAP_ESCAPE_FILTER)`（或等价函数）对 filter 用户输入做严格转义
- 对可控字段做 allowlist（仅允许合法字符集、固定属性名、限制长度）
- 禁止直接字符串拼接 filter/DN；改用参数化/模板化安全拼装（即使 PHP 无原生 LDAP 参数化，也要在代码层严格拼装）
- 给出代码搜索语句（`rg`）用于定位所有 filter/DN 拼接点
```

## tracer 证据使用说明

