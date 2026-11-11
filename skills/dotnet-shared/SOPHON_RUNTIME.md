# Sophon .NET 审计运行约束

1. 仅分析授权范围内的本地源码、项目文件和程序集。
2. 默认只做静态读取，不启动 Kestrel、IIS、IIS Express 或应用进程。
3. 不执行 `dotnet run`、`dotnet test`、`dotnet build`、`dotnet restore`。
4. 不执行 MSBuild target、Publish profile、PowerShell、批处理或项目内脚本。
5. 不自动安装 .NET SDK、NuGet 包、ILSpy、dnSpy 或扫描器。
6. 不使用发现的连接字符串、JWT 密钥、Cookie、证书或云凭据。
7. 不访问真实 URL、NuGet API、Advisory 数据库或业务系统，除非用户明确授权。
8. 输出只写当前会话工作区；临时脚本写入 `{output_path}/scripts/`。
9. 上游 Agent Teams 映射为 `pent_agent_execute`，静态任务只允许 `read_only` 或 `read_write`。
10. 无并行能力时串行执行，不得声称未运行的技能已经完成。

## 常见路径

- `.sln`、`.csproj`、`.props`、`.targets`。
- `Program.cs`、`Startup.cs`。
- `appsettings*.json`、`web.config`、`app.config`。
- `Controllers/`、`Pages/`、`Areas/`、`Middleware/`。
- `Services/`、`Repositories/`、`Data/`、`Models/`。
- `wwwroot/`、`Views/`、`Pages/Shared/`、`Components/`。
