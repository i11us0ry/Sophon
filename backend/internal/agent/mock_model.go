package agent

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type mockModel struct {
	tools []*schema.ToolInfo
}

func newMockModel() model.ToolCallingChatModel {
	return &mockModel{}
}

func (m *mockModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return &mockModel{
		tools: append([]*schema.ToolInfo(nil), tools...),
	}, nil
}

func (m *mockModel) Generate(
	_ context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.Message, error) {
	return m.next(input, opts...)
}

func (m *mockModel) Stream(
	_ context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	message, err := m.next(input, opts...)
	if err != nil {
		return nil, err
	}
	if len(message.ToolCalls) > 0 {
		return schema.StreamReaderFromArray([]*schema.Message{message}), nil
	}

	runes := []rune(message.Content)
	if len(runes) <= 1 {
		return schema.StreamReaderFromArray([]*schema.Message{message}), nil
	}
	midpoint := len(runes) / 2
	return schema.StreamReaderFromArray([]*schema.Message{
		schema.AssistantMessage(string(runes[:midpoint]), nil),
		schema.AssistantMessage(string(runes[midpoint:]), nil),
	}), nil
}

func (m *mockModel) next(input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	tools := m.tools
	if options := model.GetCommonOptions(&model.Options{}, opts...); len(options.Tools) > 0 {
		tools = options.Tools
	}
	var lastUser string
	var lastTool string
	var systemInstruction string
	for i := len(input) - 1; i >= 0; i-- {
		message := input[i]
		if message == nil {
			continue
		}
		if lastTool == "" && message.Role == schema.Tool {
			lastTool = message.Content
		}
		if lastUser == "" && message.Role == schema.User {
			lastUser = message.Content
		}
		if systemInstruction == "" && message.Role == schema.System {
			systemInstruction = message.Content
		}
		if lastUser != "" && lastTool != "" && systemInstruction != "" {
			break
		}
	}

	if lastTool != "" {
		return schema.AssistantMessage("工具执行结果："+lastTool, nil), nil
	}

	if strings.TrimSpace(lastUser) == "" {
		return schema.AssistantMessage("Mock Agent 已收到空消息。", nil), nil
	}
	// Mock 模式下用 "pent" 关键字触发原生渗透子 Agent，便于演示完整工具链路。
	if hasTool(tools, pentToolExecute) && strings.Contains(strings.ToLower(lastUser), "pent") {
		arguments, err := json.Marshal(map[string]interface{}{"task": lastUser})
		if err != nil {
			return nil, err
		}
		toolCall := schema.ToolCall{
			ID:   "mock-pent-agent-call",
			Type: "function",
			Function: schema.FunctionCall{
				Name:      pentToolExecute,
				Arguments: string(arguments),
			},
		}
		return schema.AssistantMessage("", []schema.ToolCall{toolCall}), nil
	}
	if strings.Contains(lastUser, "项目事实") && strings.Contains(systemInstruction, "项目事实") {
		return schema.AssistantMessage(
			"Mock Agent 上下文包含项目事实：\n"+extractContextSection(systemInstruction, "项目事实"),
			nil,
		), nil
	}
	if strings.Contains(lastUser, "项目背景") && strings.Contains(systemInstruction, "项目背景") {
		return schema.AssistantMessage(
			"Mock Agent 上下文包含项目背景：\n"+extractContextSection(systemInstruction, "项目背景"),
			nil,
		), nil
	}
	if strings.Contains(lastUser, "知识库") && strings.Contains(systemInstruction, "相关知识库片段") {
		return schema.AssistantMessage(
			"Mock Agent 上下文包含知识库片段：\n"+extractContextSection(systemInstruction, "相关知识库片段"),
			nil,
		), nil
	}
	return schema.AssistantMessage("Mock Agent 收到："+strings.TrimSpace(lastUser), nil), nil
}

func extractContextSection(content, marker string) string {
	index := strings.Index(content, marker)
	if index < 0 {
		return ""
	}
	value := strings.TrimSpace(content[index:])
	runes := []rune(value)
	if len(runes) > 800 {
		return string(runes[:800])
	}
	return value
}

func hasTool(tools []*schema.ToolInfo, name string) bool {
	for _, item := range tools {
		if item != nil && item.Name == name {
			return true
		}
	}
	return false
}

func drainStream(stream *schema.StreamReader[*schema.Message]) (string, error) {
	defer stream.Close()
	var content strings.Builder
	for {
		message, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if message != nil {
			content.WriteString(message.Content)
		}
	}
	return content.String(), nil
}
