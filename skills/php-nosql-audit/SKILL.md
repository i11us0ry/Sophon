---
name: php-nosql-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, nosql注入, mongodb]
---

# PHP NoSQL 注入审计（php-nosql-audit）

分析 PHP 项目源码，识别用户输入如何进入 NoSQL 查询条件，并检测 operator 注入导致的鉴权绕过/数据泄露。

## 适用场景

适合请求参数、JSON 或数组经过解析后进入 MongoDB/DocumentDB 查询，需要判断用户能否控制查询结构、字段名或 operator。

## 不适用场景

只看到 MongoDB 驱动、数组参数或 `json_decode` 不能直接判定注入。输入被强制转换为标量、只进入固定字段且 operator 被拒绝时，应继续验证而不是按框架命中定级。

## 核心判断

重点是用户输入是否保留数组或对象结构进入 query/filter，以及代码是否允许 `$ne/$gt/$or/$where/$regex` 等 operator。字段白名单、类型强制和查询构造位置比数据库名称更重要。

## 证据标准

- 可确认：用户输入进入查询结构的映射、operator 可控性和最终查询执行证据闭合，并能观察到认证或数据访问行为改变。
- 待验证：存在数组输入或查询拼接，但类型处理、字段过滤或最终 sink 尚不明确。
- 判为否：输入强制转换为标量、只命中固定字段、operator 被结构性拒绝，或数据未进入实际查询。

## 决策树

- 找到查询 sink：回查 filter/condition 的构造方式和参数解析。
- 输入可为数组或对象：检查字段 allowlist、递归清洗和类型强制。
- operator 可控：验证它是否改变查询语义以及影响的是认证、读取还是写入。
- 只改变排序、分页或返回格式：降低结论并确认实际影响。
- 链路不完整：保留待验证状态，不把数据库错误当作注入成功。

## 常见误判

- 把 PHP 数组参数直接等同于 operator 注入。
- 只检查顶层键，忽略嵌套对象、点路径和多层封装。
- 忽略框架的 schema cast、ORM 类型转换和查询白名单。
- 将普通空结果、超时或数据库报错视为查询语义已被控制。
- 为验证注入执行批量修改或删除真实业务数据。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-NOSQL-{序号}`

## 必检 Sink（可选）常见于 MongoDB 驱动/ODM：
- `collection->find($filter)`
- `findOne($filter)` / `update($filter, {value})` / `delete($filter)`
- `where($condition)` 或 `->filter({value})`
- 将用户输入拼入查询数组/表达式的封装函数

## 必检危险模式（可选）形成结论时说明以下判断证据：
- 用户输入直接作为 filter/condition 数组的一部分（尤其是 `json_decode` 的结果）
- 存在“把用户输入当成结构化条件”的行为，而未强制类型/白名单
- query 中包含可能被滥用的运算符字段：`$ne/$gt/$lt/$or/$and/$where/$regex`

## tracer 触发条件
当用户输入是 JSON/数组/嵌套结构，且进入查询构造前有多层封装时，必须追踪到最终 sink。

## 条目记录建议
- 位置证据（查询构造函数/最终 find/update 调用）
- 数据流链（输入解析 -> 类型 -> 查询条件）
- 可利用前置条件（鉴权状态/需要登录与否/能否改变查询操作符）
- 验证 PoC（必须真实路由与真实参数名；payload 为结构化 NoSQL 条件示例）
- 修复建议（严格字段 allowlist + 强制类型 + 避免把用户输入当作查询表达式）

## 证据引用（有 trace 时）
每条 NoSQL 注入疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **NOSQL 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_NOSQL_QUERY_CONSTRUCTION`：NoSQL 查询构造点证据（对应 find/update/delete 或 query builder 执行点）
2. `EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE`：用户输入进入查询条件结构的证据（可控字段进入 filter/where 的结构）
3. `EVID_NOSQL_OPERATOR_INJECTION_FIELDS`：operator 注入字段证据（$ne/$gt/$or/$where/$regex 等）

## tracer 证据使用说明

