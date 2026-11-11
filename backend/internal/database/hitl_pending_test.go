package database

import (
	"context"
	"testing"
	"time"
)

func TestPendingHITLConversationIDs(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-pending", "待审批测试")
	addTestConversation(t, db, "conv-done", "已审批测试")
	now := time.Now().UTC()

	for _, item := range []HITLRequest{
		{
			ID:             "hitl-pending",
			ConversationID: "conv-pending",
			UserID:         "user-1",
			ToolName:       "exec",
			Status:         "pending",
			CreatedAt:      now,
		},
		{
			ID:             "hitl-approved",
			ConversationID: "conv-done",
			UserID:         "user-1",
			ToolName:       "nmap",
			Status:         "pending",
			CreatedAt:      now,
		},
	} {
		if err := db.CreateHITLRequest(ctx, item); err != nil {
			t.Fatalf("创建审批请求失败: %v", err)
		}
	}
	if err := db.DecideHITLRequest(ctx, "hitl-approved", "user-1", true, "ok", "user-1"); err != nil {
		t.Fatalf("更新审批状态失败: %v", err)
	}
	if err := db.DecideHITLRequest(ctx, "hitl-pending", "user-2", true, "越权", "user-2"); err == nil {
		t.Fatalf("其他用户不应能处理审批请求")
	}

	result, err := db.PendingHITLConversationIDs(ctx, "user-1")
	if err != nil {
		t.Fatalf("读取待审批会话失败: %v", err)
	}
	if !result["conv-pending"] {
		t.Fatalf("待审批会话应存在: %+v", result)
	}
	if result["conv-done"] {
		t.Fatalf("已审批会话不应存在: %+v", result)
	}
}
