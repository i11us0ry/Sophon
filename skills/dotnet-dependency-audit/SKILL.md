---
name: dotnet-dependency-audit
description: >-
  .NET / NuGet 依赖安全审计。用于分析 .csproj、.sln、packages.lock.json、Directory.Packages.props、NuGet.Config 和程序集元数据，识别直接依赖、传递依赖、中央版本和已知漏洞。
metadata:
  tags: [dotnet, nuget, sca, 依赖审计]
---

# .NET / NuGet 依赖安全审计

## 适用场景

适合分析 `.csproj`、`packages.lock.json`、`project.assets.json`、中央包管理文件或已发布程序集，需要确定实际解析版本、依赖关系及受影响组件是否被使用。

## 不适用场景

`PackageReference` 版本范围或包名命中 advisory 不能直接证明应用漏洞。缺少 lock/assets、组件未被加载、目标功能未启用，或没有可达调用时，只能标记组件风险或待验证。

## 核心判断

结论应分为三层：锁定版本是否受影响、组件是否被项目和代码实际加载、漏洞对应功能能否由真实入口触达。还需要考虑目标框架、传递依赖、私有包和运行时缓解。

## 证据标准

- 可确认：解析版本、直接/传递关系、代码或配置引用和可达触发点证据闭合。
- 待验证：版本或包元数据命中，但缺少加载、调用、配置或路由证据。
- 判为否：锁定版本不在影响区间、包未解析或未加载、功能被禁用且无可达入口。

## 决策树

- 优先读取 lock/assets：确定实际解析包和版本。
- 匹配 advisory：核对包 ID、影响区间、目标框架和修复版本。
- 搜索项目引用：确认直接依赖、传递依赖、私有替换或本地 DLL。
- 关联代码和入口：判断受影响功能是否实际使用并可触发。
- 只有版本命中：输出待验证组件风险，不直接确认漏洞。

## 常见误判

- 用 `.csproj` 的版本范围代替实际锁定版本。
- 忽略中央包管理、传递依赖、fork、私有源和本地 DLL。
- 假设包被加载，却没有代码引用或运行时依赖证据。
- 把同一 advisory 的影响范围直接等同当前项目影响。
- 自动 restore、build 或联网查询来补结果。

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

