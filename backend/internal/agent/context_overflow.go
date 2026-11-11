package agent

import "strings"

// contextOverflowMarkers 覆盖主流 OpenAI 兼容端点与 Anthropic 的上下文超限报错文案。
var contextOverflowMarkers = []string{
	"context length",
	"context_length",
	"maximum context",
	"max context",
	"context window",
	"context overflow",
	"too many tokens",
	"token limit",
	"tokens exceed",
	"exceeds the context",
	"input is too long",
	"prompt is too long",
	"request too large",
	"上下文长度",
	"超过最大上下文",
}

// isContextOverflowError 判断上游错误是否为上下文超限，用于触发降级重试。
func isContextOverflowError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range contextOverflowMarkers {
		if strings.Contains(message, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}
