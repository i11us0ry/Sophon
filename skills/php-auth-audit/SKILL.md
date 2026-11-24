---
name: php-auth-audit
metadata:
  tags: [代码审计, php, 鉴权, 认证, 越权]
description: PHP Web 源码鉴权机制审计工具。从源码中识别所有认证/鉴权实现并分析风险，输出路由-鉴权映射与漏洞分析（含 PoC 与修复建议）。
---

# PHP 鉴权机制审计（Auth Audit）

分析 PHP Web 项目源码，识别认证与授权链路，判断每条路由的鉴权状态，并检测鉴权绕过/越权/IDOR 风险。

## 适用场景

适合已经识别出 PHP 路由，需要判断全局认证、局部授权、资源归属和鉴权绕过风险。

## 不适用场景

如果路由尚未建立，不应直接宣称项目不存在鉴权问题。仅看到 Session/JWT 或中间件名称，也不代表真实权限已闭合。

## 核心判断

鉴权结论必须同时回答认证入口、授权策略、资源归属和实际 handler 是否受保护。不同路由共享中间件时也要检查排除路径和局部覆盖。

## 证据标准

- 路由需要绑定鉴权中间件、Filter、Policy 或自定义校验位置。
- 授权缺口需要证明请求能到达敏感操作。
- IDOR 需要对象来源、Owner/Tenant 条件和实际访问结果。
- 只有 `AllowAnonymous` 或缺少检查时，先标记候选，不直接确认。

## 决策树

- 路由和全局中间件明确：建立路由-鉴权矩阵。
- 路由被排除或匿名：检查敏感动作和资源范围。
- 只认证不授权：检查角色、租户和对象所有权。
- 动态权限无法解析：标记不确定并补证据。
- 已验证绕过或越权：输出最小 PoC 和影响。

## 常见误判

- 没有显式 auth 就认定未授权。
- 只看登录态，不看资源授权。
- 忽略路由前缀、异常分支和 glob 排除。
- 把 401/403 差异当成唯一证据。
- 用伪造对象 ID 证明影响但未取得有效响应。

## 分析要求

- 优先处理 `php-route-mapper` 中已识别且可达的路由
- 识别认证链：Session/JWT/中间件/自定义校验函数
- 输出路由-鉴权映射表；无法判断的路由说明证据缺口
- 对可疑点给出：位置证据 + 数据流链 + 可利用性分析 + 验证 PoC + 修复建议

## 漏洞分级
详见：`shared/SEVERITY_RATING.md`

## 识别鉴权实现（按需）按框架识别：
- Laravel：
  - `middleware('auth'|'can'|'role:')`
  - `Auth::check()/Auth::user()`
  - Policies/Gates：`Gate::allows`、`->can({value})`
  - 路由保护：`Route::middleware([{value}])->group({value})`
- Symfony：
  - security.yaml / access_control
  - `denyAccessUnlessGranted`、`isGranted`
  - voter/policy
- 原生 PHP：
  - `session_start` + `$_SESSION` 判断
  - `if (!isset($_SESSION['user']))`/`requireLogin()`
  - 自定义函数：`checkAuth/authorize/hasRole/isAdmin`

## 路由-鉴权映射（按需）对每条路由输出以下状态：
- ✅ 公开：显式允许，无鉴权检查
- ✅ 受保护：存在完整认证/授权检查
- ⚠️ 仅认证：只校验登录态，无角色/资源级授权
- ❌ 无鉴权：没有任何鉴权链路命中
- ❓ 不确定：动态权限/复杂自定义逻辑导致难判（仍必须写出证据点）

并输出风险类型：`AUTH`，包括：
- 认证绕过（登录态校验被绕过）
- 授权绕过/越权（角色校验缺失或错误）
- IDOR（对象访问缺少所有权/归属校验）

## 可疑模式检测（按需）### 1) 路径/URI 匹配导致鉴权绕过
在 PHP 中常见根因：
- 用原始 `$_SERVER['REQUEST_URI']` 或 `parse_url` 结果做白名单匹配，但路径未规范化
- 编码/大小写/重复斜杠/尾部字符差异导致匹配失败（实际路由进入受保护 handler）

形成结论时说明：
- 白名单检查位置与代码片段
- 绕过请求（PoC）与命中的 handler 证据

### 2) 仅校验登录态，缺少角色/资源授权
形成结论时说明：
- 路由的“认证检查”位置
- “授权检查缺失”位置（例如只判断 `user!=null` 后直接执行敏感操作）

### 3) IDOR/越权
形成结论时说明：
- 敏感对象 id 来自哪里（GET/POST/URL）
- 用于查询/更新的“归属校验”是否存在（WHERE 里是否包含 user_id/owner_id）
- 未校验的原因与可达性

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。
```
├── auth_audit_report_{timestamp}.md
├── auth_mapping_{timestamp}.md
└── auth_README_{timestamp}.md
```
参考规则：
- `STATIC_MAPPING`：记录鉴权分桶映射即可；没有 trace 时明确标记覆盖范围
- `TRACE_AUDIT`：有 trace 时记录完整鉴权映射、风险结论和证据引用

### 文件1：主报告 `auth_audit_report_{timestamp}.md`
包含：
- 鉴权框架识别（含版本/实现证据）
- 鉴权架构概览（middleware/函数/handler）
- 风险统计
- 每条风险的完整漏洞结构（编号/分级/数据流/PoC/修复）

### 文件2：映射表 `auth_mapping_{timestamp}.md`
只列路由与鉴权状态、所需角色/条件（不要放漏洞详细分析）。
可选新增分桶字段（用于流水线阶段 3 选路）：
- `p_bucket`：`P0` 或 `P1`
  - `P0`：❌ 无鉴权
  - `P1`：⚠️ 仅认证，或检测到存在授权绕过/越权/IDOR 风险（即使鉴权状态显示为“仅认证”，也要在 `p1_reason` 里说明为什么进入 P1）
- `p1_reason`：一段简短静态依据（如“仅登录态，缺少 hasRole/authorize 或缺少 owner_id 校验”）

### 文件3：说明文档 `auth_README_{timestamp}.md`
只说明方法论、工具与验证指南，不包含具体漏洞细节。

## PoC 验证模板（可选）必须区分至少以下场景：
- 未登录访问（无 cookie/session/JWT）
- 普通用户访问（普通账号 cookie/JWT）
- 管理员/高权限对照（如适用）

PoC 可优先使用可执行 HTTP 请求代码块，并尽量使用真实路由规则。

## 证据引用（按运行模式参考）
- `STATIC_MAPPING`：可只说明鉴权分级与 P0/P1 分桶依据，不要求 trace 的 `EVID_*` 证据点。
- `TRACE_AUDIT`：每条疑似鉴权风险有对应 trace 时优先引用 trace 输出中的证据（允许状态标记为待验证，但证据引用必须存在）：
1. `EVID_AUTH_PATH_PROTECTED_MATCH`：路由进入受保护 handler 的路径匹配证据（对应 trace 的分支路径证据）
2. `EVID_AUTH_TOKEN_DECODE_JUDGMENT`：登录态/Token 解码结果如何被判断的证据（对应 trace 中 session/JWT 读取与条件分支）
3. `EVID_AUTH_PERMISSION_CHECK_EXEC`：权限判断函数或条件语句（如 `hasRole/authorize`）的执行证据（trace sink 定位或分支证据）
4. `EVID_AUTH_IDOR_OWNERSHIP_CONDITION`：IDOR 归属校验（WHERE/条件）是否包含 owner_id/user_id 的证据（trace 中最终查询条件或状态更新语句）

## tracer 证据使用说明
- `TRACE_AUDIT`：若 trace 契约校验失败或无法定位 1~4 任一关键证据点：该风险只能标记为 `⚠️待验证`，不得给出 `✅已确认可利用` 或“确定可绕过”的结论。

