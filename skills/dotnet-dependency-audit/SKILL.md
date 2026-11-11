---
name: dotnet-dependency-audit
description: >-
  .NET / NuGet 依赖安全审计。用于分析 .csproj、.sln、packages.lock.json、Directory.Packages.props、NuGet.Config 和程序集元数据，识别直接依赖、传递依赖、中央版本和已知漏洞。
metadata:
  tags: [dotnet, nuget, sca, 依赖审计]
---

# .NET / NuGet 依赖安全审计

## 输入

- `.csproj`、`.fsproj`、`.vbproj`。
- `.sln`、`Directory.Build.props`、`Directory.Packages.props`。
- `packages.lock.json`、`project.assets.json`。
- `NuGet.Config`、私有源配置。
- 已发布的程序和程序集目录。

## 分析步骤

1. 识别目标框架、运行时和项目类型。
2. 提取 `PackageReference`、`PackageVersion`、`DotNetCliToolReference`。
3. 解析版本范围、中央包管理和条件引用。
4. 合并直接依赖和传递依赖。
5. 标记内部包、私有源、本地 DLL 和不可解析依赖。
6. 只基于本地规则或用户提供的漏洞数据匹配风险。

## 重点组件

- Identity、JWT、OAuth、OpenIdConnect。
- Newtonsoft.Json、System.Text.Json、DataContractSerializer。
- EF Core、Dapper、MongoDB、Cosmos。
- ASP.NET Core、MVC、WebForms 和 WCF。
- Logging、Serializer、Template、Archive、Image、XML。
- Authentication、CORS、Swagger、HealthChecks。

## 漏洞判断

必须区分：

- 受影响版本。
- 当前锁定版本。
- 直接依赖或传递依赖。
- 是否存在可达调用。
- 是否启用相关功能。
- 是否有运行时或配置缓解。

仅凭包名和版本命中不得直接写 `CONFIRMED`。没有入口和调用证据时最多 `NEEDS_VALIDATION`。

## 命令约束

默认不执行：

- `dotnet restore`
- `dotnet build`
- `dotnet list package --vulnerable`
- `dotnet nuget` 网络查询
- `NuGet.exe restore`

这些命令可能联网、写缓存或执行 MSBuild。只有用户明确授权且不修改项目时才可使用。

## 输出

```text
| package | resolved_version | direct | target | advisory | call_site | status | confidence |
```

报告必须包含未解析包、私有源、静态 DLL 和传递依赖盲区。
