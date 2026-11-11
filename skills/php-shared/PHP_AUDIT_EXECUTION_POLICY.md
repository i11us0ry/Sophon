# PHP 审计执行策略

本文件用于补齐上游引用但未提供的执行策略，并覆盖来源技能中的主动执行描述。

## 安全边界

1. 仅分析用户授权的本地 PHP 源码。
2. 默认只做静态读取和代码分析。
3. 不启动 PHP-FPM、Apache、Nginx、Composer、测试或项目脚本。
4. 不访问目标 URL、内网地址、云元数据或第三方 API。
5. 不发送报告中生成的 HTTP 请求或 PoC。
6. 不安装 Composer、PHP 扩展或系统依赖。
7. 不执行 `composer audit`，除非用户明确授权联网和外置命令。

## 路径约束

- 输入使用用户提供的源码路径。
- 输出只写当前会话工作区。
- 临时脚本和中间产物写入 `{output_path}/scripts/`，禁止写 `/tmp`。
- 不修改源码、锁文件或 Composer 配置。

## Agent 约束

- 上游 Cursor/Claude Code 的 Agent 机制不直接适用。
- Sophon 中使用 `pent_agent_execute`。
- 静态审计只允许 `read_only` 或 `read_write`。
- 禁止主动测试模式。
- 无并发能力时串行执行，禁止伪造完成状态。

## 报告约束

- PoC 只能作为静态验证模板。
- 无运行时证据时不得声称已实际利用。
- 失败、缺失和未闭合证据必须写入报告。
