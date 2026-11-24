---
name: php-codeigniter-audit
metadata:
  tags: [代码审计, php, codeigniter, 框架审计, csrf]
description: CodeIgniter 框架特效安全审计工具。针对 CodeIgniter 的 CSRF、XSS 输出过滤、数据库查询构造、路由与验证器配置、会话 Cookie 安全等机制进行白盒静态审计，并映射到通用漏洞类型体系（CSRF/AUTH/XSS/SQL/CFG/SESS 等）。
---

# PHP CodeIgniter 框架安全审计（php-codeigniter-audit）

分析 CodeIgniter 项目的框架机制与配置踩坑，重点覆盖：
- CSRF 保护是否启用与 token 名称/校验逻辑是否正确
- 输出过滤与 XSS 防护（CI 自带过滤器是否被禁用或错误使用）
- 数据库查询构造：是否存在用户输入拼接到 `$this->db->query` 或原生 SQL
- 表单验证器是否被覆盖或绕过
- 会话 Cookie flags 安全性（CI 会话设置）

## 适用场景

适合确认目标使用 CodeIgniter，需要审计 CSRF、XSS、查询构造、鉴权和会话配置。

## 不适用场景

没有框架识别证据时，不应按 CodeIgniter 规则推断漏洞。框架默认配置与实际运行时覆盖需要分开判断。

## 核心判断

先确认 CI 版本、配置加载和路由保护，再判断框架机制是否真正生效。默认配置、配置文件和环境覆盖可能不同。

## 证据标准

- 框架识别需要目录、配置或版本证据。
- CSRF/XSS/SQL/AUTH/SESS 结论需要实际入口和配置证据。
- 框架过滤器或 helper 存在不等于所有路由生效。
- 实际影响不足时标记待验证。

## 决策树

- 框架版本明确：读取对应配置和安全机制。
- 发现状态变更路由：检查 CSRF 是否覆盖。
- 发现用户输入输出：检查视图转义。
- 发现原生查询：检查 SQL 拼接和绑定。
- 配置存在但运行时不确定：标记环境依赖。

## 常见误判

- 把 CI 默认安全配置当成项目实际配置。
- 看到 XSS filter 就认定所有输出安全。
- 看到 Query Builder 就忽略原生查询。
- 忽略过滤器和路由分组。
- 把 Cookie 标志缺失直接当成会话劫持。

## 框架识别
先确认项目确实是 CodeIgniter，再应用本技能的框架规则：
- 典型目录：`application/`、`system/`
- 配置文件：`application/config/config.php` 或会话/安全配置文件
- 版本线索：`composer.json` 或 `system/core/` 结构

## 风险归类
只有形成 finding 时再写明：
- 通用类型码：`CSRF` / `XSS` / `SQL` / `AUTH` / `CFG` / `SESS` / `LOGIC` 等
- 映射原因

## 条件化审计路径
按实际路由、filters 和配置选择检查点，不要求逐项填表。

### 1) CSRF 保护（CSRF）
按需检查：
- CSRF 是否启用（CI 3：`config.php` 的 csrf 配置，CI 4：Security 类配置）
- token 名称、校验入口与跳过规则（是否某些控制器/方法未启用校验）

判定规则：
- 存在状态变更路由但未启用 CSRF，则输出 CSRF 风险

### 2) XSS 输出防护（XSS/CFG）
按需检查：
- CI 的 XSS 过滤器是否启用（如 `global_xss_filtering`、`Security::xss_clean` 等）
- 视图层是否对用户输入做了正确 `html_escape` 或等价转义

判定规则：
- 如果禁用过滤或未转义输出，且用户输入能进入视图输出，则输出 XSS

### 3) 数据库查询拼接（SQL）
按需检查：
- 原生查询：`$this->db->query($sql)` 或 `->query($userInput)` 的拼接证据
- 正确路径：Query Builder 与绑定参数使用

判定规则：
- 若存在用户输入进入 SQL 字符串拼接，输出 SQL 风险

### 4) 会话与 Cookie（SESS/CFG）
按需检查：
- cookie flags：HttpOnly/Secure/SameSite（如在项目中配置）
- session 配置：会话超时、固定防护（如存在）

### 5) 鉴权与访问控制（AUTH）
按需检查：
- 控制器中访问保护模式：自定义 `auth` helper、基类 controller 的校验、过滤器
- 路由层过滤器或中间件（CI 4 filters）

判定规则：
- 若敏感控制器或方法缺少统一鉴权，输出 AUTH 风险

## 项目写回
- 已检查并排除的 controller、filter 或配置写 `project_record_audit(action=cell)`。
- 需要运行时请求或配置条件的假设写 `project_plan_hypotheses`。
- 只有证据闭合后才调用 `project_report_finding`。
- 没有证据的检查项不生成空报告。

