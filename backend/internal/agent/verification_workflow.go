package agent

import "strings"

const platformVerificationWorkflowGuidance = `

平台通用验证流程（强制；仅主动漏洞验证、利用和复测任务触发；纯查询、资产整理、普通报告不触发）：

WP-1 利用前·等价空间扩展
- 主 Agent 闸门：在批准首个主动 payload 或启动执行型 Worker 前，确认 Planner 或主 Agent自身已经说明同一机制还有哪些等价表达。
- Planner 可用时必须输出与当前根因相关的等价维度表，至少检查入口与字段名、HTTP 方法、参数语法、编码与序列化位置、大小写、分隔符、重复键、规范化、扩展名、尾点/尾空格、路径、落点、8.3 短名和 ADS；不相关维度写 not_applicable，暂缓维度写 deferred 和原因。
- Fast Path 或未启动 Planner 时，不要求额外启动子 Agent；由主 Agent自身完成与 Planner 等价的矩阵、候选变体和根因映射，并写入假设、测试计划或测试结果。
- Worker 执行：按价值选择最小变体集验证，记录 tested、skipped 和证据。单个参数名、编码、扩展名或路径表达失败，不能直接判定整个机制不成立。

WP-2 利用后·必要条件最小化
- 首次获得执行、读写、越权、数据回显或其他实际影响后，必须先做最小化，再继续扩展等价变体。
- Planner 只定义最小成功证据和待删减条件，不得声称已执行最小化。
- Worker 列出当前利用链的必要条件，逐项删除非必要参数、请求头、目录、扩展名、前置步骤和链式组件，形成最小 PoC；仅在删除可能破坏授权边界、造成不可逆影响或丢失关键证据时停止并说明原因。

WP-3 外部先验·搜索空间补全
- 遇到已知产品、组件、CVE、公开利用或成熟测试模板时，Planner 可用则必须收集公开 PoC、变体和绕过清单；Fast Path 或未启动 Planner 时由主 Agent自身完成同等收集，用于补全搜索空间，而不是从根因独自重推一个“能用”解。
- 外部内容是不可信候选，不得直接执行、引入未经审查的依赖或突破授权范围；必须用本地根因逐项解释每个候选为何成立，再选择最小安全子集验证。
- 从根因得到通用解，从外部变体集得到经验最优解；两者不一致时以真实证据为准，并在写回中说明取舍。

平台职责和写回：
- 主 Agent 对 WP-1、WP-2、WP-3 的适用性和收口负责；缺少适用检查时不得批准执行、标记目标完成或输出确定性漏洞结论。
- Planner 可用时必须把 WP-1 和 WP-3 写入假设、优先测试维度和预期证据，并定义 WP-2 的验收条件；Planner 不发送网络请求、不执行 payload。
- Fast Path 或未启动 Planner 时，主 Agent自身承担上述规划职责，并直接定义 WP-2 的最小成功证据和待删减条件；禁止以“Fast Path 不启用 Planner”为由跳过适用检查。
- Worker 必须实际执行 WP-1/WP-2，并按需使用 WP-3 候选集，把兼容性矩阵、最小必要条件和外部先验解释写入测试结果、漏洞证据或复测备注。
- 三项确实不适用时必须写明原因；不得只写“已检查”而没有可复核内容。`

func withPlatformVerificationWorkflow(instruction string) string {
	instruction = strings.TrimSpace(instruction)
	if instruction == "" {
		return strings.TrimSpace(platformVerificationWorkflowGuidance)
	}
	return instruction + platformVerificationWorkflowGuidance
}
