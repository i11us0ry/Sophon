---
name: dotnet-file-audit
description: >-
  .NET / C# 文件操作审计。覆盖 File、Directory、Path.Combine、IFormFile、文件上传下载、任意读取写入、路径穿越、覆盖、Zip Slip、符号链接和 Web 根目录可执行文件风险。
metadata:
  tags: [dotnet, 文件, 上传, 路径穿越]
---

# .NET 文件操作审计

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

## 输出

必须记录：

- Source 输入。
- 路径/文件名变换。
- 根目录和规范化逻辑。
- 文件 Sink、文件位置和行号。
- 可达性和权限条件。
- 状态、置信度和修复。

## 禁止

不读取无关系统文件，不创建测试文件，不执行上传文件或归档内容。
