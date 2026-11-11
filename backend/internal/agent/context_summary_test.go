package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
)

type stubSummaryModel struct {
	content string
}

func (m *stubSummaryModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	return schema.AssistantMessage(m.content, nil), nil
}

func (m *stubSummaryModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage(m.content, nil)}), nil
}

func (m *stubSummaryModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func openDigestTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "digest.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	now := time.Now().UTC()
	if err := db.CreateConversation(context.Background(), database.Conversation{
		ID:          "conv-digest",
		OwnerUserID: "user-1",
		Title:       "digest",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	return db
}

func TestToolDigestPairsCallsAndResults(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	details := []database.ProcessDetail{
		{
			ID: "call-1", ConversationID: "conv-digest", MessageID: "msg-1",
			EventType: "tool_call", Message: "exec",
			Data: map[string]interface{}{
				"toolCallId": "call-1",
				"arguments":  `{"command":"nmap -sV 10.0.0.1"}`,
			},
			CreatedAt: now,
		},
		{
			ID: "result-1", ConversationID: "conv-digest", MessageID: "msg-1",
			EventType: "tool_result", Message: "exec",
			Data: map[string]interface{}{
				"toolCallId": "call-1",
				"result":     "22/tcp open ssh\n80/tcp open http",
			},
			CreatedAt: now.Add(time.Millisecond),
		},
	}
	for _, detail := range details {
		if err := db.AddProcessDetail(ctx, detail); err != nil {
			t.Fatalf("写入过程明细失败: %v", err)
		}
	}

	service := &Service{db: db, cfg: config.Config{}}
	digest := service.toolDigest(ctx, "conv-digest")
	for _, want := range []string{"exec", "nmap -sV 10.0.0.1", "22/tcp open ssh 80/tcp open http"} {
		if !strings.Contains(digest, want) {
			t.Fatalf("工具摘要缺少 %q: %q", want, digest)
		}
	}
	if strings.Contains(digest, "[未返回结果]") {
		t.Fatalf("已配对的结果不应标记未返回: %q", digest)
	}
}

func TestToolDigestKeepsLastPairs(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for index := 0; index < 10; index++ {
		if err := db.AddProcessDetail(ctx, database.ProcessDetail{
			ID:             "call-" + string(rune('a'+index)),
			ConversationID: "conv-digest",
			EventType:      "tool_call",
			Message:        "tool-" + string(rune('0'+index)),
			Data: map[string]interface{}{
				"toolCallId": "call-" + string(rune('a'+index)),
				"arguments":  "{}",
			},
			CreatedAt: now.Add(time.Duration(index) * time.Millisecond),
		}); err != nil {
			t.Fatalf("写入过程明细失败: %v", err)
		}
	}

	service := &Service{db: db, cfg: config.Config{}}
	digest := service.toolDigest(ctx, "conv-digest")
	if strings.Contains(digest, "- tool-1(") {
		t.Fatalf("应只保留最近 %d 对工具调用: %q", toolDigestMaxPairs, digest)
	}
	for _, want := range []string{"- tool-2(", "- tool-9("} {
		if !strings.Contains(digest, want) {
			t.Fatalf("工具摘要缺少 %q: %q", want, digest)
		}
	}
}

func TestSummarizeHistoryUsesModelAndFallsBack(t *testing.T) {
	messages := []database.Message{
		{Role: "user", Content: "扫描 10.0.0.1"},
		{Role: "assistant", Content: "已确认 22 端口开放"},
	}
	ctx := context.Background()

	withModel := &Service{model: &stubSummaryModel{content: "模型生成的摘要"}}
	if got := withModel.summarizeHistory(ctx, "旧摘要", messages); got != "模型生成的摘要" {
		t.Fatalf("应使用模型摘要，实际 %q", got)
	}

	withoutModel := &Service{}
	want := mergeSummary("", messages, summaryInputRunes)
	if got := withoutModel.summarizeHistory(ctx, "", messages); got != want {
		t.Fatalf("模型不可用时应回退拼接摘要，实际 %q", got)
	}
}

func TestRecentWindowStartBudgetModes(t *testing.T) {
	content := strings.Repeat("a", 100)
	messages := []database.Message{
		{Role: "user", Content: content},
		{Role: "assistant", Content: content},
		{Role: "user", Content: content},
	}
	if got := recentWindowStart(messages, 60, true); got != 1 {
		t.Fatalf("token 预算应保留最近两条，实际起点 %d", got)
	}
	if got := recentWindowStart(messages, 60, false); got != 2 {
		t.Fatalf("字符预算应只保留最近一条，实际起点 %d", got)
	}
}

func TestBuildModelMessagesInjectsToolDigest(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.AddMessage(ctx, database.Message{
		ID: "msg-user", ConversationID: "conv-digest", Role: "user",
		Content: "计算 1+2", CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID: "msg-assistant", ConversationID: "conv-digest", Role: "assistant",
		Content: "结果是 3", CreatedAt: now.Add(time.Millisecond),
	}); err != nil {
		t.Fatalf("写入助手消息失败: %v", err)
	}
	if err := db.AddProcessDetail(ctx, database.ProcessDetail{
		ID: "digest-call", ConversationID: "conv-digest", MessageID: "msg-assistant",
		EventType: "tool_call", Message: "calculator",
		Data:      map[string]interface{}{"toolCallId": "call-1", "arguments": `{"a":1,"b":2}`},
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入工具调用失败: %v", err)
	}
	if err := db.AddProcessDetail(ctx, database.ProcessDetail{
		ID: "digest-result", ConversationID: "conv-digest", MessageID: "msg-assistant",
		EventType: "tool_result", Message: "calculator",
		Data:      map[string]interface{}{"toolCallId": "call-1", "result": "3"},
		CreatedAt: now.Add(time.Millisecond),
	}); err != nil {
		t.Fatalf("写入工具结果失败: %v", err)
	}

	service := &Service{db: db, cfg: config.Config{}}
	messages, err := service.buildModelMessages(ctx, "conv-digest", "user-1")
	if err != nil {
		t.Fatalf("组装模型消息失败: %v", err)
	}
	if len(messages) == 0 || messages[0].Role != schema.System {
		t.Fatalf("首条消息应为系统提示: %+v", messages)
	}
	state := lastStateMessage(t, messages)
	if !strings.Contains(state, "最近工具执行记录") || !strings.Contains(state, "calculator") {
		t.Fatalf("状态包未注入工具摘要: %q", state)
	}
}
