---
name: php-route-mapper
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 路由, 参数映射, 接口梳理]
---

# PHP 源码 Route & Param Mapper

分析 PHP Web 项目源码，提取**完整**的 HTTP 路由入口与请求参数结构，生成可用于安全测试的请求模板（Burp/Repeater 风格），并自动保存为 Markdown。

## 适用场景

适合需要从 PHP 源码建立路由、参数、处理器和请求模板索引，且这些信息后续确实用于鉴权审计或数据流追踪。

## 不适用场景

如果只需要验证一个已知路由，或项目没有可识别的路由分发逻辑，不必为了完整性枚举全部文件。

## 核心判断

路由映射的价值是建立可达入口和参数结构，不是追求数量。优先输出可追踪到处理器的路由、动态参数和来源明确的请求结构。

## 证据标准

- 每条路由至少应绑定路径、HTTP 方法、处理器位置和参数来源。
- 行号缺失时要标记待定位，不虚构位置。
- 动态路由需要记录约束和可控参数。
- 请求模板只作为后续验证输入，不代表漏洞成立。

## 决策树

- 路由定义明确：记录处理器和参数来源。
- 路由由重写或 front controller 分发：继续追踪到实际 handler。
- 路径有动态参数：记录约束、类型和可控性。
- 无法确定处理器：标记待定位，不把路由当作已确认入口。
- 路由数量过多：优先业务入口、鉴权边界和高风险参数面。

## 常见误判

- 把静态文件路径当成动态路由。
- 把框架约定参数当成已确认可控。
- 把反代或容器前缀混入源码路由。
- 为了“完整”输出大量无处理器、无参数的噪声。
- 把请求模板当成漏洞 PoC。

## 写回要求

优先覆盖所有已识别且可追踪的 HTTP 路由与接口；无法定位或不适用的条目应说明原因：
- 不使用省略占位符隐藏关键路由
- 不只输出“关键路由/重要路由”
- 已知路由尽量包含 HTTP 方法、路径规则、处理器位置、参数结构和请求模板

## 材料发现
从当前项目工作区、会话附件和项目事实中自动定位 PHP 源码。若存在反向代理或网关前缀，只有在代码或部署配置有证据时才拼接完整路径。

路由、参数和校验结果写回项目审计台账或当前任务结果，不强制创建固定目录。

## 识别范围（按需）1. 路由配置/定义（按框架识别）
   - Laravel：`routes/web.php`、`routes/api.php`、`Route::get/post/{subpath}`、`Route::resource`、Route group 前缀与中间件
   - Symfony：`config/routes/*`、PHP8 attribute `#[Route({route_options})]`、Annotation `@Route({route_options})`
   - Slim：`$app->get/post/any({handler})`、自定义中间件
   - WordPress：`admin-post.php`/`admin-ajax.php`、`add_action('admin_post_*')`、`add_action('wp_ajax_*')`
   - 纯 PHP：front controller（如 `public/index.php`）的分发逻辑、基于 `$_SERVER['REQUEST_URI']` 的路由匹配
2. 动态路由/参数化路由（必做）
   - `{id}` / `(?P<id>{id_pattern})` / 正则路由：必须把可控参数列出来
   - 路由约束（where/regex limit）：形成结论时说明约束规则与可控性边界

## 参数结构解析（按需）对每条路由输出以下参数来源与类型信息：
- Path 参数：来自路由规则的占位（输出如 `{id}`）
- Query 参数：`$_GET` / `request()->query({query})` / 框架 query 解析结果
- Body 参数：`php://input`、`$_POST`、JSON `json_decode({json})`
- Header 参数：`getallheaders()`、`$_SERVER[{value}]`、框架 request header API
- Cookie 参数：`$_COOKIE`
- File 参数：`$_FILES`（输出字段名与 filename 来源）

## 处理器位置（按需）每条路由必须给出处理器来源证据：
- 文件路径（相对/绝对均可，但必须一致）
- 函数/类/方法签名（在源码中能定位到的名称）
- 关键分发点：路由匹配如何进入 handler（如 switch case / include 文件链）

## 建议记录格式
### `routes_{timestamp}.md`：主索引（逐条列出）
说明：本 skill 使用 `routes_{timestamp}.md` 中 `=== [N] {route_summary} ===` 的 `N` 作为 **HTTP 路由**的 `route_id`（流水线后续用于 `route_tracer/{route_id}/trace_{timestamp}.md` 文件分桶）。**CLI / hook / sink-only** 等合成 `route_id` 由 `php-audit-pipeline` 阶段 3 写入 `high_risk_routes_{timestamp}.md`，**不**占用本文件的 `[N]` 序号。
```markdown
# {project_name} - 路由与接口索引（PHP）
生成时间: {timestamp}
分析路径: {source_path}

## 路由清单（全部）
=== [1] GET /path/to/{id} ===
HTTP 方法: GET
路由路径规则: /path/to/{id}
处理器: ControllerClass@method / functionName
位置: path/to/file.php:line（若无法获取行号，标注“待定位：需人工打开文件确认”但仍给出文件路径）
参数概览:
  Path: id (类型推断/约束)
  Query: {query_params}

=== [2] POST /path/to/{id}/action ===
HTTP 方法: POST
路由路径规则: /path/to/{id}/action
处理器: ControllerClass@action / functionName
位置: path/to/file.php:line（若无法获取行号，标注“待定位：需人工打开文件确认”但仍给出文件路径）
参数概览:
  Path: id (类型推断/约束)
  Query: {query_params}
```

### `params_{timestamp}.md`：参数详细（逐条列出）
```markdown
# {project_name} - 路由参数结构（逐条）
生成时间: {timestamp}

=== 路由: GET /path/to/{id} ===
1) Path 参数
| 参数 | 类型/约束 | 位置 | 必填 |
|------|------------|------|------|
| id   | int/regex{id_pattern} | Router rule | 是/否/不确定 |

2) Query 参数
| 参数 | 类型 | 来源 | 必填 | 说明 |

3) Body 参数（如 JSON）
| 字段 | 类型 | JSON 路径 | 必填 |

4) Header/ Cookie / File（如有）
| 字段 | 类型 | 来源 | 必填 |

5) 完整请求模板（必须在代码块里）
```http
GET /path/to/{id}?a={a}&b={b} HTTP/1.1
Host: {host}
Cookie: {cookie}
Authorization: Bearer {token}
Content-Type: application/json

{"k":"{v}"}

## 交付前检查
- [ ] routes 与 params 中每条路由“序号/路由标识”一致
- [ ] 没有出现省略占位符
- [ ] 每条路由都有“完整请求模板”代码块

