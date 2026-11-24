package toolerror

import "strings"

type Class string

const (
	Policy            Class = "policy"
	Authorization     Class = "authorization"
	Authentication    Class = "authentication"
	Network           Class = "network"
	TargetUnreachable Class = "target_unreachable"
	Timeout           Class = "timeout"
	RateLimit         Class = "rate_limit"
	CommandExit       Class = "command_exit"
	NoMatch           Class = "no_match"
	Tool              Class = "tool_error"
	InvalidArguments  Class = "invalid_arguments"
	Cancelled         Class = "cancelled"
	Unknown           Class = "unknown"
)

func Classify(message string) Class {
	message = strings.ToLower(strings.TrimSpace(message))
	switch {
	case message == "":
		return Unknown
	case containsAny(message, "rate limit", "too many requests", "status code: 429", "status code 429", "限流", "冷却"):
		return RateLimit
	case containsAny(message, "timeout", "timed out", "deadline exceeded", "超时"):
		return Timeout
	case containsAny(message, "context canceled", "context cancelled", "取消"):
		return Cancelled
	case containsAny(message, "命令无匹配结果", "未匹配到结果", "no matches found", "no match found"):
		return NoMatch
	case containsAny(message, "命令退出码", "command exit code", "exit status"):
		return CommandExit
	case containsAny(
		message,
		"no such host",
		"name or service not known",
		"could not resolve",
		"no route to host",
		"network is unreachable",
		"connection refused",
		"无法解析",
		"不可达",
	):
		return TargetUnreachable
	case containsAny(
		message,
		"connection reset",
		"temporary network",
		"temporary failure",
		"tls handshake",
		"bad gateway",
		"status code: 502",
		"status code: 503",
		"status code: 504",
		"proxy",
		"网络错误",
	):
		return Network
	case containsAny(
		message,
		"credential",
		"unauthorized",
		"status code: 401",
		"status code 401",
		"invalid api key",
		"incorrect api key",
		"invalid_api_key",
		"authentication",
		"invalid token",
		"api key",
		"认证失败",
		"登录失效",
		"凭据",
	):
		return Authentication
	case containsAny(message, "审批", "forbidden", "permission denied", "status code: 403", "status code 403", "权限不足"):
		return Authorization
	case containsAny(
		message,
		"policy",
		"mission policy",
		"拦截设置",
		"能力模式拒绝",
		"拒绝执行",
		"工具策略",
		"策略拒绝",
		"已停用",
		"禁止通过 nohup",
		"禁止通过 setsid",
		"禁止通过 disown",
		"后台子进程",
		"进程组超出预算",
	):
		return Policy
	case containsAny(
		message,
		"parse arguments",
		"invalid argument",
		"unmarshal",
		"invalid json",
		"unexpected end of json",
		"json: cannot",
		"json 参数",
		"参数",
		"不能为空",
		"必须是",
		"仅支持",
		"tool_name",
	):
		return InvalidArguments
	default:
		return Tool
	}
}

func Normalize(class Class) Class {
	switch class {
	case Policy,
		Authorization,
		Authentication,
		Network,
		TargetUnreachable,
		Timeout,
		RateLimit,
		CommandExit,
		NoMatch,
		Tool,
		InvalidArguments,
		Cancelled,
		Unknown:
		return class
	case "":
		return Unknown
	default:
		return Tool
	}
}

func Retryable(class Class) bool {
	switch Normalize(class) {
	case Timeout, RateLimit, Network:
		return true
	default:
		return false
	}
}

func Blocked(class Class) bool {
	switch Normalize(class) {
	case Policy, Authorization, Authentication:
		return true
	default:
		return false
	}
}

func NextActions(class Class) []string {
	switch Normalize(class) {
	case Policy, Authorization, Authentication:
		return []string{"检查授权、凭据或工具策略，不得用等价方式绕过"}
	case Timeout, Network:
		return []string{"确认网络、目标可达性和超时设置后重试", "禁止原样重复失败命令"}
	case TargetUnreachable:
		return []string{"确认目标地址、端口和网络路径后重试", "目标持续不可达时说明原因并跳过"}
	case RateLimit:
		return []string{"等待冷却或降低并发后重试"}
	case CommandExit:
		return []string{"检查命令输出、路径和退出码对应的具体错误", "修改命令或参数后重试", "禁止原样重复失败命令"}
	case NoMatch:
		return []string{"确认查询范围、文件名和匹配条件", "无匹配可作为负结果记录，不必原样重试"}
	case InvalidArguments:
		return []string{"修正参数格式或补齐必填项后重试", "禁止原样重复失败命令"}
	case Cancelled:
		return []string{"等待用户恢复或重新发起任务"}
	default:
		return []string{
			"先分析错误类型和可修复性",
			"修改命令、参数或执行方式后重试",
			"禁止原样重复失败命令",
			"不得用等价方式绕过安全策略",
		}
	}
}

func containsAny(value string, items ...string) bool {
	for _, item := range items {
		if strings.Contains(value, strings.ToLower(item)) {
			return true
		}
	}
	return false
}
