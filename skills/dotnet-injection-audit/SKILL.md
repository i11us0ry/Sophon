---
name: dotnet-injection-audit
description: >-
  .NET / C# 注入与危险 Sink 审计。覆盖 ADO.NET、EF Core、Dapper、NoSQL、动态 LINQ、Process、PowerShell、表达式引擎、模板以及 HttpClient/WebRequest/SSRF。
metadata:
  tags: [dotnet, 注入, sql, ssrf, rce]
---

# .NET 注入与危险 Sink 审计

## 适用场景

适合已发现数据库、命令、表达式、模板、HTTP 客户端或其他危险 Sink，需要确认输入是否可控、是否进入危险上下文以及是否具备实际影响。

## 不适用场景

如果只有危险 API 名称、没有入口和参数流证据，不应直接形成漏洞结论。

## 核心判断

注入是否成立取决于：输入是否可控、路径是否可达、Sink 是否处理未参数化数据、是否存在有效阻断。方法名和表面字符串形态不能代替完整链路。

## 证据标准

- SQL 注入需要完整 SQL 文本来源、参数化状态和执行点。
- 命令注入需要参数进入命令、参数列表或脚本执行点的证据。
- SSRF 需要 URL 可控、请求实际发出和访问目标证据。
- 模板/表达式注入需要可控表达式进入执行引擎。
- 只有静态候选时标记待验证，不写 confirmed。

## 决策树

- Sink 明确：回查参数来源和调用链。
- 使用参数化 API：确认参数是否真实绑定。
- 动态标识符或完整 SQL 透传：继续追踪下游执行。
- 防护存在：判断是否覆盖所有输入路径。
- 入口不可达或参数不可控：记录负结果或降级。

## 常见误判

- 只搜索字符串拼接，漏掉完整 SQL 形参透传。
- 看到参数化 API 就认为绝对安全。
- 把动态表名、排序或 `IN` 列表当成普通参数。
- 把 URL 来自配置直接视为安全。
- 把扫描器或正则命中当成可利用。

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

