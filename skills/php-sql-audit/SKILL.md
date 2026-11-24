---
name: php-sql-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, sql注入, 数据库]
---

# PHP SQL 注入审计（php-sql-audit）

分析 PHP 项目源码，识别 SQL 执行相关代码（PDO/mysqli/ORM），追踪用户输入到 SQL 构造点，验证是否存在 SQL 注入，并输出完整漏洞报告。

## 适用场景

适合源码中已经出现数据库执行点或完整 SQL 文本透传，需要判断参数来源、参数化状态和执行影响。

## 不适用场景

只出现 `query`、`exec`、`DB::raw` 等函数名时，不能直接认定注入。无路由和数据流证据时应先补充入口。

## 核心判断

SQL 注入必须同时满足：输入可控、进入 SQL 文本或动态标识符、执行点实际使用未参数化数据。ORM、Prepare 和字符串外形都不能单独证明安全或危险。

## 证据标准

- SQL 执行点位置和 SQL 文本构造过程。
- 参数来源、转换、拼接、参数化与绑定状态。
- 分支可达性和执行上下文。
- 缺失任一关键证据时标记待验证。

## 决策树

- 发现 SQL 执行点：回查完整 SQL 文本来源。
- 使用参数化 API：确认绑定参数真实存在。
- 完整 SQL 形参透传：追踪到最终执行点和参数集合。
- 动态表名、排序、分页：检查白名单。
- 证据闭合：输出漏洞；否则保留候选。

## 常见误判

- 只搜索字符串拼接，漏掉完整 SQL 透传。
- 看到 Prepare 就判定安全。
- 把 ORM 方法名当成参数化保证。
- 把错误回显直接当成注入成功。
- 未证明参数可控就确认漏洞。

## 审计要求

- 优先审计可达路由参数进入 SQL 的路径
- 使用数据流追踪证据判定可利用性；不得只靠关键字猜测
- 已知漏洞和关键证据不得用省略占位符隐藏

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-SQL-{序号}`

## 可用上下文

已有路由、参数或调用链结果时可直接复用，用于判断参数来源和实际使用状态；没有时从源码直接扫描 SQL Sink、入口和参数流，不因缺少上游报告阻塞审计。

## SQL Sink 识别（按需）1. PDO / PDOStatement
   - 相对危险：`$pdo->query($sql)` / `$pdo->exec($sql)`（若 $sql 来自拼接/包含用户输入）
   - 形式检查：`$pdo->prepare($sql)` 只有在 `$sql` 中使用占位符且后续 `bindParam/bindValue` 或正确传参时更安全
   - ORM/DB 包装：`DB::select(DB::raw({value}))`、Doctrine `createQuery` 等
2. mysqli / mysqli_stmt
   - `mysqli_query($conn, $sql)` 拼接危险
   - `mysqli_prepare` 只有 prepare + bind 正确时才可能安全
3. 典型危险构造模式（必做）
   - SQL 字符串与变量拼接：`.`, `sprintf`, `vsprintf`, `implode/join` + SQL 关键字
   - 动态排序：`order by $x` / `ORDER BY ".$x."`（常见高危）

## 需要触发 tracer 的条件（按需）满足任一条时，可优先调用 `php-route-tracer` 或使用等价的代码追踪证据：
- 参数经过多层传递或 JSON 解码后取字段进入 SQL
- SQL 构造点位于基类/工具类/父函数中
- 存在分支条件（if/try/catch）导致 SQL 是否执行不确定

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。
```
└── sql_{timestamp}.md
```

## 漏洞报告条目模板（可选）```markdown
### [{等级前缀}-SQL-{序号}] {风险标题}

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source → Sink）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常/环境依赖}

#### 证据引用（可参考 php-route-tracer）
每条 SQL 疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **SQL 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_SQL_EXEC_POINT`：SQL 执行函数/语句位置（对应 trace 的 SQL 执行点证据）
2. `EVID_SQL_STRING_CONSTRUCTION`：SQL 字符串构造/拼接位置（对应 trace 的 SQL 拼接证据）
3. `EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT`：用户可控参数到 SQL 片段的映射（对应 trace 的可控性矩阵字段证据）

#### tracer 证据缺失处理（可选）
- 若无法定位上述 1~3 任一关键证据要点：该漏洞状态只能标记为 `⚠️待验证`，不得直接给出 `✅已确认可利用`。

#### 验证 PoC（按需，可执行请求）
```http
{HTTP Method} {完整路径与查询/Body} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

#### 建议修复
- 给出安全写法要点（PDO prepare + bind 且保证 SQL 片段不拼接用户输入）
- 给出代码搜索语句（`rg`/`grep` 风格）用于定位所有同类拼接点
```

## 结论质量检查（非必填）
- [ ] 至少输出：风险统计 + 每条漏洞完整条目
- [ ] 不出现任何省略占位符
- [ ] 每条漏洞都包含：数据流链、可利用前置条件、可执行 PoC、修复建议

