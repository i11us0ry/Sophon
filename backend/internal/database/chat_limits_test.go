package database

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCreateHITLRequestRejectsOversizedArguments(t *testing.T) {
	db := openConversationTestDB(t)
	err := db.CreateHITLRequest(context.Background(), HITLRequest{
		ID:             "hitl-large",
		ConversationID: "conv-large",
		UserID:         "user-1",
		ToolName:       "exec",
		Arguments: map[string]interface{}{
			"command": strings.Repeat("A", maxHITLArgumentsBytes),
		},
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatalf("超大 HITL 参数应被拒绝")
	}
}

func TestAddProcessDetailBoundsLargeData(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-detail-limit", "限制测试")
	if err := db.AddProcessDetail(ctx, ProcessDetail{
		ID:             "pd-large",
		ConversationID: "conv-detail-limit",
		EventType:      "tool_result",
		Message:        "exec",
		Data: map[string]interface{}{
			"result": strings.Repeat("A", maxProcessDetailDataBytes),
		},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入过程详情失败: %v", err)
	}

	items, err := db.ListProcessDetails(ctx, "conv-detail-limit", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("读取过程详情失败: %+v err=%v", items, err)
	}
	if truncated, _ := items[0].Data["truncated"].(bool); !truncated {
		t.Fatalf("超大过程详情应被截断: %+v", items[0].Data)
	}
}
