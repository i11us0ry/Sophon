package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
)

const (
	toolDigestMaxPairs    = 8
	toolDigestMaxRunes    = 1500
	toolDigestArgsRunes   = 160
	toolDigestResultRunes = 300
	summaryInputRunes     = 6000
	// minor 压缩输出更紧（增量合并），major 压缩允许更长（全量重写、消除摘要漂移）。
	summaryOutputRunesMinor = 600
	summaryOutputRunesMajor = 1200
	summaryTimeout          = 30 * time.Second
)

// summaryCallResult 记录一次摘要调用的产出与用量，用于审计与 token 记账。
type summaryCallResult struct {
	Text             string
	PromptTokens     int
	CacheReadTokens  int
	CompletionTokens int
	TotalTokens      int
	Estimated        bool
	Model            string
	LatencyMs        int64
}

// 结构化摘要模板：固定章节，保证压缩后目标/约束/凭据/漏洞/进度不丢。
const summarySystemPrompt = `你是安全测试对话的压缩助手。只输出结构化摘要，禁止调用任何工具，禁止编造事实。
必须保留：授权范围与约束、凭据与认证细节（原文保留）、已确认漏洞与 PoC 要点、工具核心结论、
失败尝试与死路、当前进度与下一步，以及所有用户消息的意图。无信息的章节写“无”。`

const summarySections = `请把下面的对话历史压缩成结构化摘要，严格按以下章节输出（无信息写“无”）：

## 1. 授权范围与约束
- 目标/范围/禁止项、用户指定的方法、优先级与否定约束

## 2. 资产与服务枚举
- 关键资产短表或数量+代表样例、已识别服务/端口要点、资产状态

## 3. 架构与已知薄弱点

## 4. 已确认漏洞与攻击路径
- 漏洞名、URL/路径、参数/Payload、PoC 要点、影响等级、攻击链步骤

## 5. 工具核心发现
- 各工具结论（概括，不抄日志）、重复发现合并

## 6. 所有用户消息
- 逐条列出用户消息要点，保留关键约束原文

## 7. 当前进度、失败与下一步
- 已完成/进行中/卡点、失败尝试及结论、下一步具体操作`

// toolDigest 把最近的工具调用与结果压缩成短摘要，供下一轮模型了解已执行过的工具。
func (s *Service) toolDigest(ctx context.Context, conversationID string) string {
	if s.db == nil || strings.TrimSpace(conversationID) == "" {
		return ""
	}
	details, err := s.db.ListRecentProcessDetails(ctx, conversationID, toolDigestMaxPairs*10)
	if err != nil {
		return ""
	}

	type toolEntry struct {
		name   string
		args   string
		result string
	}
	var order []*toolEntry
	byCallID := map[string]*toolEntry{}
	for _, detail := range details {
		callID, _ := detail.Data["toolCallId"].(string)
		switch detail.EventType {
		case "tool_call":
			args, _ := detail.Data["arguments"].(string)
			entry := &toolEntry{name: detail.Message, args: args}
			if callID != "" {
				byCallID[callID] = entry
			}
			order = append(order, entry)
		case "tool_result":
			result, _ := detail.Data["result"].(string)
			if entry := byCallID[callID]; entry != nil {
				entry.result = result
				continue
			}
			order = append(order, &toolEntry{name: detail.Message, result: result})
		}
	}

	if len(order) > toolDigestMaxPairs {
		order = order[len(order)-toolDigestMaxPairs:]
	}
	var builder strings.Builder
	used := 0
	for _, entry := range order {
		line := "- " + strings.TrimSpace(entry.name)
		if args := strings.TrimSpace(entry.args); args != "" {
			line += "(" + truncateHead(args, toolDigestArgsRunes) + ")"
		}
		if result := strings.TrimSpace(entry.result); result != "" {
			line += " → " + truncateHead(result, toolDigestResultRunes)
		} else {
			line += " → [未返回结果]"
		}
		line = strings.ReplaceAll(line, "\n", " ")
		lineRunes := len([]rune(line))
		if used > 0 && used+lineRunes+1 > toolDigestMaxRunes {
			break
		}
		if used > 0 {
			builder.WriteString("\n")
			used++
		}
		builder.WriteString(line)
		used += lineRunes
	}
	return strings.TrimSpace(builder.String())
}

// summarizeHistory 优先用模型压缩历史，失败或未返回内容时回退到拼接摘要。
func (s *Service) summarizeHistory(
	ctx context.Context,
	previous string,
	messages []database.Message,
) string {
	result := s.summarizeOlderMessages(ctx, previous, messages, "")
	if strings.TrimSpace(result.Text) == "" {
		return mergeSummary(previous, messages, summaryInputRunes)
	}
	return result.Text
}

func (s *Service) generateHistorySummary(ctx context.Context, folded string) (string, error) {
	text, _, _, _, _, err := s.callStructuredSummary(ctx, folded, "")
	return text, err
}

// callStructuredSummary 调用摘要模型并返回用量；先剥离工具，避免摘要阶段触发工具调用。
func (s *Service) callStructuredSummary(
	ctx context.Context,
	folded string,
	transcriptPath string,
) (string, int, int, int, bool, error) {
	if s.model == nil || strings.TrimSpace(folded) == "" {
		return "", 0, 0, 0, true, fmt.Errorf("摘要模型不可用")
	}
	chatModel := s.model
	if withoutTools, err := chatModel.WithTools(nil); err == nil && withoutTools != nil {
		chatModel = withoutTools
	}
	summaryCtx, cancel := context.WithTimeout(ctx, summaryTimeout)
	defer cancel()
	prompt := summarySections + "\n\n待压缩内容：\n\n" + folded
	if strings.TrimSpace(transcriptPath) != "" {
		prompt += "\n\n（原始对话已保存到: " + transcriptPath + "）"
	}
	message, err := chatModel.Generate(summaryCtx, []*schema.Message{
		schema.SystemMessage(summarySystemPrompt),
		schema.UserMessage(prompt),
	})
	if err != nil {
		return "", 0, 0, 0, true, err
	}
	if message == nil {
		return "", 0, 0, 0, true, fmt.Errorf("摘要模型未返回内容")
	}
	promptTokens := estimateTextTokensV2(folded) + estimateTextTokensV2(summarySections) + 32
	cacheReadTokens := 0
	completionTokens := estimateTextTokensV2(message.Content)
	estimated := true
	if message.ResponseMeta != nil && message.ResponseMeta.Usage != nil {
		usage := message.ResponseMeta.Usage
		promptTokens = usage.PromptTokens
		cacheReadTokens = usage.PromptTokenDetails.CachedTokens
		completionTokens = usage.CompletionTokens
		estimated = false
	}
	if cacheReadTokens < 0 {
		cacheReadTokens = 0
	}
	if cacheReadTokens > promptTokens {
		cacheReadTokens = promptTokens
	}
	return strings.TrimSpace(message.Content), promptTokens, cacheReadTokens, completionTokens, estimated, nil
}

// summarizeOlderMessages 结构化压缩一段历史；失败时回退为头尾截断的拼接摘要，绝不中断调用方。
func (s *Service) summarizeOlderMessages(
	ctx context.Context,
	previous string,
	messages []database.Message,
	transcriptPath string,
) summaryCallResult {
	folded := mergeSummary(previous, messages, summaryInputRunes)
	return s.summarizeText(ctx, folded, summaryOutputRunesMinor, transcriptPath)
}

// summarizeText 对已拼接好的文本执行结构化摘要；失败时回退为头尾截断的原文摘要。
func (s *Service) summarizeText(
	ctx context.Context,
	folded string,
	outputRunes int,
	transcriptPath string,
) summaryCallResult {
	if outputRunes <= 0 {
		outputRunes = summaryOutputRunesMinor
	}
	started := time.Now()
	text, promptTokens, cacheReadTokens, completionTokens, estimated, err := s.callStructuredSummary(
		ctx,
		folded,
		transcriptPath,
	)
	latency := time.Since(started).Milliseconds()
	if err != nil || strings.TrimSpace(text) == "" {
		return summaryCallResult{
			Text:      truncateMessageContent(folded, outputRunes),
			Estimated: true,
			Model:     s.configSnapshot().LLMModel,
			LatencyMs: latency,
		}
	}
	text = truncateMessageContent(text, outputRunes)
	if strings.TrimSpace(transcriptPath) != "" {
		text += "\n\n原始对话记录: " + transcriptPath
	}
	total := promptTokens + completionTokens
	if total <= 0 {
		total = estimateTextTokensV2(text)
	}
	return summaryCallResult{
		Text:             text,
		PromptTokens:     promptTokens,
		CacheReadTokens:  cacheReadTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      total,
		Estimated:        estimated,
		Model:            s.configSnapshot().LLMModel,
		LatencyMs:        latency,
	}
}

// recentWindowStart 从后向前累计预算，返回需要保留的最近消息起始下标。
func recentWindowStart(candidates []database.Message, budget int, tokens bool) int {
	start := len(candidates)
	used := 0
	for index := len(candidates) - 1; index >= 0; index-- {
		content := candidates[index].Content
		if strings.TrimSpace(content) == "" {
			start = index
			continue
		}
		size := len([]rune(content)) + 32
		if tokens {
			size = estimateTextTokens(content) + 4
		}
		if used+size > budget && start < len(candidates) {
			break
		}
		used += size
		start = index
	}
	return start
}

// truncateHead 保留开头 max 个字符，超出部分用省略号标记。
func truncateHead(value string, max int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= max {
		return string(runes)
	}
	return string(runes[:max]) + "…"
}
