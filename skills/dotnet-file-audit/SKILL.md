---
name: dotnet-file-audit
description: >-
  .NET / C# 文件操作审计。覆盖 File、Directory、Path.Combine、IFormFile、文件上传下载、任意读取写入、路径穿越、覆盖、Zip Slip、符号链接和 Web 根目录可执行文件风险。
metadata:
  tags: [dotnet, 文件, 上传, 路径穿越]
---

# .NET 文件操作审计

## 适用场景

适合读取、下载、上传、写入、覆盖或解压接口，需要判断请求输入是否能控制最终文件路径以及写后是否可访问或执行。

## 不适用场景

看到 `Path.Combine`、`IFormFile` 或文件 API 不能直接确认路径穿越或任意上传。固定路径、可靠根目录约束、随机文件名、隔离存储或不可触达落点需要降低结论。

## 核心判断

文件风险取决于最终解析路径而不是初始字符串。应分别判断 source、规范化、根目录前缀、符号链接、文件名、内容类型、覆盖策略、运行权限和写后访问执行条件。

## 证据标准

- 可确认：真实入口、路径/内容控制、最终落点、约束缺口和读取/写入/执行效果证据闭合。
- 待验证：存在拼接或上传，但规范化、根目录、文件权限、访问映射或落点尚未确认。
- 判为否：路径固定在允许目录、`GetFullPath` 后前缀校验可靠、文件不可触达，或写入被权限阻断。

## 决策树

- 找到文件 sink：回查 source 和最终路径构造。
- 检查规范化：判断 `GetFullPath`、基目录和路径分隔符比较。
- 检查上传：分析文件内容、原始名称、扩展名和服务器命名。
- 检查解压：逐 entry 判断规范化和目标根目录约束。
- 检查写后效果：确认 Web 映射、执行、包含、下载和访问权限。

## 常见误判

- `Path.Combine` 出现就认定路径穿越。
- 存在 `GetFullPath` 就认为安全，忽略 base 前缀比较和符号链接。
- 原始文件名可控就认定可以覆盖任意文件。
- 文件进入 Web 目录就认定 ASP.NET 会执行。
- 为验证读取系统文件、创建测试文件或执行归档内容。

## 读取与包含

检查：

- `File.ReadAllText/ReadAllBytes/OpenRead`。
- `StreamReader`、`FileStream`、`MemoryMappedFile`。
- `File.ReadLines`、`XDocument.Load`、配置加载。
- `Path.Combine` 后是否经过 `GetFullPath` 和根目录约束。
- 是否允许绝对路径、`..`、UNC、符号链接和替代路径。

## 写入与覆盖

- `File.WriteAllText/WriteAllBytes/AppendAllText`。
- `FileStream`、`StreamWriter`、`BinaryWriter`。
- `File.Copy`、`File.Move`、`File.Replace`。
- `Directory.Delete`、`File.Delete`。
- 是否验证目标目录、文件名、扩展名、覆盖策略和权限。

## 上传

检查：

- `IFormFile`、`FormFile`、`Request.Form.Files`。
- `CopyToAsync`、`OpenReadStream`、`SaveAsAsync`。
- 原始文件名、扩展名、Content-Type 和 magic bytes。
- 文件名清理、随机命名、目标目录和上传大小限制。
- 上传目录是否能被 Web 访问或执行。
- 同名覆盖、路径穿越、ADS、Unicode 和大小写绕过。

## 下载

- `PhysicalFile`、`FileStreamResult`、`FileResult`。
- Content-Disposition 文件名注入。
- 路径是否来自用户，是否允许目录穿越。
- MIME 类型和浏览器嗅探。

## 解压与归档

- `ZipFile.ExtractToDirectory`。
- `ZipArchive` entry 的 `FullName` 和 `ExtractToFile`。
- `TarFile`、第三方归档库。
- 检查 entry 规范化、目标目录约束、符号链接和覆盖。

## 路径安全判断

安全路径通常需要：

1. 以固定根目录为基础。
2. 使用 `Path.GetFullPath` 规范化。
3. 校验结果仍位于根目录内。
4. 拒绝绝对路径、跨盘符、UNC、符号链接和危险文件名。
5. 使用随机文件名和扩展名白名单。

仅检查字符串是否包含 `..` 通常不充分。

