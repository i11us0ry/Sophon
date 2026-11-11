---
name: dotnet-injection-audit
description: >-
  .NET / C# 注入与危险 Sink 审计。覆盖 ADO.NET、EF Core、Dapper、NoSQL、动态 LINQ、Process、PowerShell、表达式引擎、模板以及 HttpClient/WebRequest/SSRF。
metadata:
  tags: [dotnet, 注入, sql, ssrf, rce]
---

# .NET 注入与危险 Sink 审计

## SQL / 数据访问

检查时不能只寻找“字符串拼接”代码。每个 SQL 执行点都要回答：

1. SQL 文本是否可能由请求参数、消息字段、父方法形参或配置完整传入？
2. 当前方法是否只是原样透传到 `DBUtils.*`、`SqlCommand`、`ExecuteDataSet`、`ExecuteReader` 等下游执行点？
3. 下游是否传入参数数组？数组是否为空、未创建、被包装层丢弃或始终使用零 `SqlParameter`？
4. helper/stored-procedure/service 封装是否改变了“SQL 文本可控但本地无拼接”的表面形态？

高风险形态包括：

- 入口参数本身是完整 SQL 文本，方法内不再拼接，随后直接执行。
- `SQLScriptServiceHelper.GetDataFromStoredProc(executeType=3) → DBUtils.ExecuteDataSet(ctx, sql)` 一类“完整 SQL 形参透传 + 零参数”链路。
- 包装层只接收 `sql`，没有地方构造 `SqlParameter` 或参数集合。
- 动态表名、列名、排序、分页、`IN` 列表通过形参传递，但在下游才进入 SQL。

不能因为当前方法没有 `+`、`String.Format`、插值字符串或 `append` 就直接判定安全。应继续追踪入参来源和最终执行 API 的参数化状态。

其他检查项：

- `SqlCommand.CommandText` 字符串拼接。
- `FromSqlRaw`、`ExecuteSqlRaw`、`ExecuteSqlInterpolated`。
- Dapper `Query`、`Execute` 和动态 SQL。
- 动态表名、列名、排序、分页和 `IN` 列表。
- `DataTable.Compute`、动态 LINQ 和 OData。

安全判断：

- 参数化参数通常阻断注入，但动态标识符仍需白名单。
- `FromSqlInterpolated` 仍需检查拼接位置。
- 字符串插值进入 raw SQL 是高价值线索。
- ORM 方法名本身不能证明安全。

## NoSQL / Cosmos / Mongo

检查：

- 用户 JSON 直接成为 filter。
- `$ne`、`$gt`、`$regex`、`$where` 等操作符注入。
- Cosmos SQL 字符串拼接和参数化。
- Lucene/Elasticsearch query string 和 DSL。

## 命令执行

检查：

- `Process.Start`、`ProcessStartInfo.FileName/Arguments`。
- `cmd.exe /c`、PowerShell、bash、脚本路径。
- `UseShellExecute`、环境变量、工作目录和参数拼接。

重点判断：

- 是否使用 `ArgumentList`。
- 是否传入独立参数而不是拼接命令字符串。
- 是否可从请求到达，且没有固定白名单。

## 表达式与模板

- `CSharpScript`、Roslyn 编译。
- 动态 LINQ、OData `$filter`、规则引擎。
- Razor Runtime Compilation、Liquid、Handlebars、自定义模板。
- `Activator.CreateInstance`、类型名可控和反射。

## SSRF 与 HTTP 客户端

检查：

- `HttpClient`、`WebRequest`、`HttpWebRequest`、`WebClient`。
- `RestSharp`、Refit、Flurl 和自定义封装。
- URL、Host、Scheme、Port、Path、Query 是否可控。
- `AllowAutoRedirect`、DNS 解析、代理、IPv4/IPv6 和十进制 IP。
- Allowlist 是否在规范化后校验，是否防止重定向和 DNS 重绑定。
- 是否能访问 loopback、RFC1918、link-local、metadata 和内部服务。

## 输出

每条发现必须包含：

- 类型：SQL、NOSQL、CMD、EXPR、TPL、SSRF。
- Source 到 Sink。
- 可控性和防护。
- 文件、行号、类和方法。
- 状态和证据置信度。
- 最小静态验证模板。
- 修复建议。

## 禁止

- 不执行命令、脚本、SQL、HTTP 请求或模板。
- 不连接数据库、MongoDB、Cosmos、Elasticsearch 或外部 URL。
- 不根据参数名或 API 名称直接判定漏洞。
