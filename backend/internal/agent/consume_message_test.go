package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

func newConsumeTestEnv(t *testing.T) (*Service, *usageTracker, context.Context) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "consume.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-consume",
		OwnerUserID: "user-1",
		Title:       "思考采集测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "msg-consume",
		ConversationID: "conv-consume",
		Role:           "assistant",
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("创建助手消息失败: %v", err)
	}
	toolCtx := execctx.WithUserID(ctx, "user-1")
	toolCtx = execctx.WithConversationID(toolCtx, "conv-consume")
	return &Service{db: db, cfg: config.Config{}},
		newUsageTracker(db, "conv-consume", "user-1", "msg-consume", nil, "chat", "test-model"),
		toolCtx
}

func TestConsumeMessageCapturesReasoningAndThinking(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	var events []Event
	progress := func(event Event) error {
		events = append(events, event)
		return nil
	}
	capture := &runCapture{}

	reasoningChunk := schema.AssistantMessage("", nil)
	reasoningChunk.ReasoningContent = "先分析目标："
	planningChunk := schema.AssistantMessage(
		"我准备调用工具检查端口。",
		[]schema.ToolCall{{
			ID:   "call-1",
			Type: "function",
			Function: schema.FunctionCall{
				Name:      "exec",
				Arguments: `{"command":"nmap"}`,
			},
		}},
	)
	assistantVariant := &adk.MessageVariant{
		IsStreaming:   true,
		Role:          schema.Assistant,
		MessageStream: schema.StreamReaderFromArray([]*schema.Message{reasoningChunk, planningChunk}),
	}
	if err := service.consumeMessage(ctx, usage, assistantVariant, capture, progress); err != nil {
		t.Fatalf("消费助手流失败: %v", err)
	}

	toolMessage := schema.ToolMessage("22/tcp open ssh", "call-1")
	toolMessage.ToolName = "exec"
	toolVariant := &adk.MessageVariant{Role: schema.Tool, Message: toolMessage}
	if err := service.consumeMessage(ctx, usage, toolVariant, capture, progress); err != nil {
		t.Fatalf("消费工具结果失败: %v", err)
	}

	finalVariant := &adk.MessageVariant{
		Role:    schema.Assistant,
		Message: schema.AssistantMessage("结论：22 端口开放。", nil),
	}
	if err := service.consumeMessage(ctx, usage, finalVariant, capture, progress); err != nil {
		t.Fatalf("消费最终回答失败: %v", err)
	}

	if !strings.Contains(capture.reasoning.String(), "先分析目标") {
		t.Fatalf("未采集推理内容: %q", capture.reasoning.String())
	}
	if final := capture.finalText(); final != "结论：22 端口开放。" {
		t.Fatalf("最终回答不应包含思考文本，实际 %q", final)
	}

	kinds := make(map[string]string)
	for _, event := range events {
		kinds[event.Type] = event.Message
	}
	if !strings.Contains(kinds["reasoning_delta"], "先分析目标") {
		t.Fatalf("缺少 reasoning_delta 事件: %+v", kinds)
	}
	if !strings.Contains(kinds["reasoning"], "先分析目标") {
		t.Fatalf("缺少持久化 reasoning 事件: %+v", kinds)
	}
	if !strings.Contains(kinds["thinking"], "我准备调用工具检查端口") {
		t.Fatalf("缺少 thinking 事件: %+v", kinds)
	}
	if kinds["tool_call"] != "exec" || kinds["tool_result"] != "exec" {
		t.Fatalf("工具事件异常: %+v", kinds)
	}

	details, err := service.db.ListProcessDetails(ctx, "conv-consume", 50)
	if err != nil {
		t.Fatalf("读取过程明细失败: %v", err)
	}
	types := make(map[string]bool)
	for _, detail := range details {
		types[detail.EventType] = true
	}
	for _, want := range []string{"reasoning", "thinking", "tool_call", "tool_result"} {
		if !types[want] {
			t.Fatalf("过程明细缺少 %s: %+v", want, details)
		}
	}
}
