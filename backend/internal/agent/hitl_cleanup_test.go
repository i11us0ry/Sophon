package agent

import (
	"context"
	"testing"
)

func TestWaitForHITLClearsPendingRequestOnCancel(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()

	if err := service.waitForHITL(
		cancelledCtx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "id"},
		nil,
	); err == nil {
		t.Fatalf("取消的任务应返回错误")
	}

	pending, err := service.db.ListPendingHITLRequests(ctx, "user-1")
	if err != nil {
		t.Fatalf("读取待审批请求失败: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("取消后不应遗留待审批请求: %+v", pending)
	}
}
