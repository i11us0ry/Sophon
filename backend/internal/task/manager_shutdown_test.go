package task

import (
	"context"
	"testing"
	"time"
)

func TestManagerWaitForIdleAndCancelAll(t *testing.T) {
	manager := NewManagerWithLimit(5)
	taskItem, _, err := manager.CreateIfIdle("conversation-1", "user-1")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	cancelled := make(chan struct{})
	go func() {
		<-taskItem.Context().Done()
		close(cancelled)
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	if err := manager.WaitForIdle(waitCtx); err == nil {
		t.Fatalf("运行中的任务不应被视为空闲")
	}
	cancel()
	if count := manager.CancelAll(); count != 1 {
		t.Fatalf("应取消 1 个任务，实际 %d", count)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatalf("任务上下文未取消")
	}
	idleCtx, idleCancel := context.WithTimeout(context.Background(), time.Second)
	defer idleCancel()
	if err := manager.WaitForIdle(idleCtx); err != nil {
		t.Fatalf("取消后任务应进入空闲: %v", err)
	}
}
