# Sophon Java 审计运行约束

本文件优先于上游技能中的联网、自动执行和 Claude Code 专用流程说明。

## 安全边界

1. 仅分析用户授权的本地项目、源码、JAR、WAR 和反编译产物。
2. 默认只做静态审计，不访问目标 URL、真实接口、云元数据服务或第三方业务系统。
3. 不执行未知项目代码、构建脚本、测试、shell、class 或 jar。
4. 不自动安装 JDK、CFR、PyYAML、requests 或其他依赖。
5. 不使用发现的密钥、Token、Cookie 或证书访问真实服务。
6. OSV.dev 在线查询只在用户明确授权网络访问后使用。

## 路径与产物

- 输入路径使用用户提供的绝对路径或其工作区映射路径。
- 输出必须位于当前会话工作区。
- 临时脚本放入 `{output_path}/scripts/`，禁止写入 `/tmp`。
- 不修改用户源码。

## Agent 映射

- 上游 Claude Code 的 Agent Teams、TaskCreate、spawn、SendMessage 不由 Sophon 原生提供。
- Sophon 中使用 `pent_agent_execute`，静态审计限定 `read_only` 或 `read_write`。
- 无并行能力或并发不足时串行执行，禁止声称未执行的 agent 已完成。

## 结论要求

- 结论必须绑定文件、类、方法、行号和参数流。
- 危险模式、可达路径、参数可控和可利用性分开判断。
- 未完成运行时验证时，候选利用链不得标记为已确认。
