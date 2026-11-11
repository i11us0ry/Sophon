package agent

import (
	"context"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	// 未显式配置 token 预算时，按字符预算的 0.75 保守折算。
	contextCharToTokenRatioNum = 3
	contextCharToTokenRatioDen = 4
	minContextTokens           = 4000
	fallbackContextChars       = 24000
	// 估算安全系数：避免估算偏低导致上游 context overflow。
	tokenEstimateSafetyPct = 108
)

// estimateTextTokensV2 估算文本 token 数：
// 中日韩等宽字符约 1 token/字，ASCII 字母数字约 4 字符/token，其余符号约 2 字符/token，
// 最后乘安全系数，宁可略高估也不要低估。
func estimateTextTokensV2(content string) int {
	content = strings.TrimSpace(content)
	if content == "" {
		return 0
	}
	wide := 0
	word := 0
	symbol := 0
	for _, r := range content {
		switch {
		case unicode.Is(unicode.Han, r), unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r), unicode.Is(unicode.Hangul, r):
			wide++
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			word++
		case r < 128:
			symbol++
		default:
			wide++
		}
	}
	tokens := wide + (word+3)/4 + (symbol+1)/2
	if tokens < 1 {
		tokens = 1
	}
	return (tokens*tokenEstimateSafetyPct + 99) / 100
}

// estimateMessagesTokensV2 估算一组模型消息的 token 总量，含每条消息的固定开销。
func estimateMessagesTokensV2(messages []*schema.Message) int {
	total := 0
	for _, message := range messages {
		if message == nil {
			continue
		}
		total += estimateTextTokensV2(message.Content) + 4
		if message.ReasoningContent != "" {
			total += estimateTextTokensV2(message.ReasoningContent)
		}
		for _, call := range message.ToolCalls {
			total += estimateTextTokensV2(call.Function.Name)
			total += estimateTextTokensV2(call.Function.Arguments)
		}
	}
	return total
}

func estimateToolsTokens(ctx context.Context, items []tool.BaseTool) int {
	total := 0
	for _, item := range items {
		if item == nil {
			continue
		}
		info, err := item.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		raw, err := json.Marshal(info)
		if err != nil {
			continue
		}
		total += estimateTextTokensV2(string(raw)) + 8
	}
	return total
}

// contextBudgetTokens 返回当前生效的上下文 token 预算：
// 优先 agent.context_max_tokens；未配置时按 agent.context_max_chars 的 0.75 折算。
func (s *Service) contextBudgetTokens() int {
	snapshot := s.configSnapshot()
	if snapshot.AgentContextMaxTokens > 0 {
		return snapshot.AgentContextMaxTokens
	}
	chars := snapshot.AgentContextMaxChars
	if chars < minContextTokens {
		chars = fallbackContextChars
	}
	tokens := chars * contextCharToTokenRatioNum / contextCharToTokenRatioDen
	if tokens < minContextTokens {
		tokens = minContextTokens
	}
	return tokens
}
