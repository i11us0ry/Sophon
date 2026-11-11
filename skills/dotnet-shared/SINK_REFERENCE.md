# .NET 审计 Sink 参考

## 数据访问

- ADO.NET：`SqlCommand.CommandText`、`ExecuteReader`、`ExecuteScalar`、`ExecuteNonQuery`。
- EF Core：`FromSqlRaw`、`ExecuteSqlRaw`、`ExecuteSqlInterpolated`、动态 LINQ。
- Dapper：`Query`、`QueryAsync`、`Execute`、`ExecuteAsync`。
- NoSQL：MongoDB filter、Cosmos DB 查询和动态表达式。
- ORM 原生 SQL、字符串模板和拼接查询。

检查参数化、字段白名单、排序字段、表名和动态条件。

## 命令与表达式

- `Process.Start`、`ProcessStartInfo.Arguments`。
- PowerShell、CMD、bash 和自定义脚本执行。
- `CSharpScript`、Roslyn 动态编译、`Activator.CreateInstance`。
- `DataTable.Compute`、动态 LINQ、表达式字符串和模板引擎。

## 反序列化

- `BinaryFormatter`、`LosFormatter`、`ObjectStateFormatter`、`NetDataContractSerializer`。
- Newtonsoft.Json `TypeNameHandling`。
- `DataContractSerializer` 动态类型。
- `XmlSerializer` 动态类型加载。
- ViewState、Session 序列化和自定义序列化封装。

## XML

- `XmlDocument.Load/LoadXml`。
- `XmlReaderSettings.DtdProcessing`、`XmlResolver`。
- `XDocument.Load`、`XPathDocument`。
- `DataSet.ReadXml`、`XmlSerializer`。

检查 DTD、外部实体、URL resolver 和网络访问。

## 文件

- `File.ReadAllText`、`ReadAllBytes`、`OpenRead`。
- `File.WriteAllText`、`WriteAllBytes`、`AppendAllText`。
- `Directory.*`、`Path.Combine`、`FileInfo`、`DirectoryInfo`。
- `ZipFile.ExtractToDirectory`、`ZipArchive` entry。
- `IFormFile`、`CopyToAsync`、`SaveAsAsync`、`PhysicalFileProvider`。

重点检查规范化、根目录约束、文件名、落点、覆盖和可执行目录。

## HTTP 与 SSRF

- `HttpClient.GetAsync/PostAsync/SendAsync`。
- `WebRequest.Create`、`HttpWebRequest`、`WebClient`。
- `RestSharp`、`Refit` 和自定义 HTTP 封装。
- `HttpClientHandler.AllowAutoRedirect`、代理、DNS 和 URL 解析。

## Web 输出

- Razor `Html.Raw`。
- Blazor `MarkupString`、`NavigationManager.NavigateTo`。
- `Content(..., "text/html")`、`File(..., "text/html")`。
- `Response.Headers`、`Response.Cookies`、`Redirect`、`LocalRedirect`。

## 鉴权与配置

- `[Authorize]`、`[AllowAnonymous]`、`AddAuthentication`、JWT Bearer。
- Cookie Authentication、Identity、Policy、Role、Claim。
- `UseCors`、`AddCors`、`UseHsts`、`UseExceptionHandler`。
- `DataProtection`、MachineKey、Cookie flags、TLS。

## 依赖

- `.csproj` PackageReference。
- `packages.lock.json`、NuGet.Config、Directory.Packages.props。
- 传递依赖、中央包版本和私服源。
