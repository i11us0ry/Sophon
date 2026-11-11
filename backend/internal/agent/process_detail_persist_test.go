package agent

import (
	"strings"
	"testing"
)

func TestPersistEventTruncatesLargeProcessDetail(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	original := strings.Repeat("x", maxStoredProcessDetailBytes+256)
	event := Event{
		Type:    "tool_result",
		Message: "exec",
		Data: map[string]interface{}{
			"toolCallId": "call-large",
			"toolName":   "exec",
			"result":     original,
		},
	}

	if err := service.persistEvent(ctx, usage.conversationID, usage.messageID, event); err != nil {
		t.Fatalf("写入过程明细失败: %v", err)
	}
	if event.Data["result"] != original {
		t.Fatal("实时事件不应被截断")
	}

	details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
	if err != nil {
		t.Fatalf("读取过程明细失败: %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("过程明细数量异常: %+v", details)
	}
	result, _ := details[0].Data["result"].(string)
	if !strings.Contains(result, "[输出超过 64KB，已截断]") {
		t.Fatalf("落库结果缺少截断标记: %q", result)
	}
	if details[0].Data["truncated"] != true {
		t.Fatalf("落库结果缺少 truncated 标记: %+v", details[0].Data)
	}
}

func TestPersistEventTruncatesLargeReasoning(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	original := strings.Repeat("r", maxStoredProcessDetailBytes+256)
	event := Event{
		Type:    "reasoning",
		Message: "reasoning",
		Data: map[string]interface{}{
			"reasoning": original,
		},
	}

	if err := service.persistEvent(ctx, usage.conversationID, usage.messageID, event); err != nil {
		t.Fatalf("写入推理过程明细失败: %v", err)
	}
	if event.Data["reasoning"] != original {
		t.Fatal("实时推理事件不应被截断")
	}

	details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
	if err != nil {
		t.Fatalf("读取过程明细失败: %v", err)
	}
	if len(details) != 1 {
		t.Fatalf("过程明细数量异常: %+v", details)
	}
	reasoning, _ := details[0].Data["reasoning"].(string)
	if !strings.Contains(reasoning, "[输出超过 64KB，已截断]") {
		t.Fatalf("落库推理缺少截断标记: %q", reasoning)
	}
	if details[0].Data["truncated"] != true {
		t.Fatalf("落库推理缺少 truncated 标记: %+v", details[0].Data)
	}
}
