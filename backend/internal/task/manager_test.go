package task

import (
	"errors"
	"testing"
	"time"
)

func TestCreateIfIdleRejectsSecondTaskForSameConversation(t *testing.T) {
	manager := NewManager()
	first, occupied, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil || first == nil || occupied != "" {
		t.Fatalf("首次创建应成功: err=%v task=%v occupied=%q", err, first, occupied)
	}

	second, busyID, err := manager.CreateIfIdle("conv-1", "user-1")
	if !errors.Is(err, ErrConversationBusy) || second != nil {
		t.Fatalf("同会话运行中不应再创建任务: err=%v task=%v", err, second)
	}
	if busyID != first.ID() {
		t.Fatalf("应返回占用中的任务 ID %s，实际 %q", first.ID(), busyID)
	}

	other, _, err := manager.CreateIfIdle("conv-2", "user-1")
	if err != nil || other == nil {
		t.Fatalf("其他会话应可创建任务")
	}

	first.Complete()
	third, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil || third == nil {
		t.Fatalf("任务结束后应可重新创建")
	}
	if third.ID() == first.ID() {
		t.Fatalf("新任务应使用新的任务 ID")
	}
}

func TestCreateIfIdleAllowsRetryAfterCancel(t *testing.T) {
	manager := NewManager()
	first, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil || first == nil {
		t.Fatalf("首次创建应成功")
	}
	first.Cancel()

	second, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil || second == nil {
		t.Fatalf("取消后应可重新创建任务")
	}
}

func TestActiveConversations(t *testing.T) {
	manager := NewManager()
	first, _, _ := manager.CreateIfIdle("conv-1", "user-1")
	second, _, _ := manager.CreateIfIdle("conv-2", "user-2")

	active := manager.ActiveConversations("user-1")
	if active["conv-1"] != StatusRunning {
		t.Fatalf("user-1 的 conv-1 应为 running: %+v", active)
	}
	if _, ok := active["conv-2"]; ok {
		t.Fatalf("不应返回其他用户的任务: %+v", active)
	}

	first.Complete()
	second.Complete()
	if len(manager.ActiveConversations("user-1")) != 0 {
		t.Fatalf("完成任务不应出现在运行状态中")
	}
}

func TestSetMaxPerUserAppliesImmediately(t *testing.T) {
	manager := NewManagerWithLimit(1)
	first, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil {
		t.Fatalf("创建首个任务失败: %v", err)
	}
	if _, _, err := manager.CreateIfIdle("conv-2", "user-1"); !errors.Is(err, ErrUserTaskLimit) {
		t.Fatalf("达到上限后应拒绝新任务: %v", err)
	}

	manager.SetMaxPerUser(2)
	second, _, err := manager.CreateIfIdle("conv-2", "user-1")
	if err != nil {
		t.Fatalf("调高上限后应允许新任务: %v", err)
	}

	manager.SetMaxPerUser(1)
	if _, _, err := manager.CreateIfIdle("conv-3", "user-1"); !errors.Is(err, ErrUserTaskLimit) {
		t.Fatalf("调低上限后应阻止超过新上限的任务: %v", err)
	}

	first.Complete()
	second.Complete()
}

func TestDetachKeepsTaskRunningAndDrainsEvents(t *testing.T) {
	manager := NewManager()
	item, _, err := manager.CreateIfIdle("conv-detach", "user-1")
	if err != nil || item == nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	item.Detach()

	published := make(chan struct{})
	go func() {
		for index := 0; index < 300; index++ {
			item.Publish(Event{Type: "delta", Message: "chunk"})
		}
		close(published)
	}()
	select {
	case <-published:
	case <-time.After(2 * time.Second):
		t.Fatalf("Detach 后事件应被后台排空，Publish 不应阻塞")
	}
	if item.Snapshot().Status != StatusRunning {
		t.Fatalf("Detach 不应改变任务运行状态")
	}
	item.Complete()
}

func TestCancelConversation(t *testing.T) {
	manager := NewManager()
	first, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil || first == nil {
		t.Fatalf("创建首个任务失败")
	}
	second, _, err := manager.CreateIfIdle("conv-2", "user-1")
	if err != nil || second == nil {
		t.Fatalf("创建第二个任务失败")
	}

	if cancelled := manager.CancelConversation("conv-1", "user-1"); cancelled != 1 {
		t.Fatalf("应取消 1 个任务，实际 %d", cancelled)
	}
	if first.Snapshot().Status != StatusCancelled {
		t.Fatalf("目标会话任务应被取消")
	}
	if second.Snapshot().Status != StatusRunning {
		t.Fatalf("其他会话任务不应被取消")
	}
}

func TestCreateIfIdleEnforcesUserLimit(t *testing.T) {
	manager := NewManagerWithLimit(2)
	if _, _, err := manager.CreateIfIdle("conv-1", "user-1"); err != nil {
		t.Fatalf("首个任务创建失败: %v", err)
	}
	if _, _, err := manager.CreateIfIdle("conv-2", "user-1"); err != nil {
		t.Fatalf("第二个任务创建失败: %v", err)
	}
	if _, _, err := manager.CreateIfIdle("conv-3", "user-1"); !errors.Is(err, ErrUserTaskLimit) {
		t.Fatalf("超过用户任务上限应被拒绝: %v", err)
	}
	if _, _, err := manager.CreateIfIdle("conv-4", "user-2"); err != nil {
		t.Fatalf("其他用户不应受当前用户上限影响: %v", err)
	}
}

func TestPublishDoesNotDropEvents(t *testing.T) {
	manager := NewManagerWithLimit(1)
	taskItem, _, err := manager.CreateIfIdle("conv-1", "user-1")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	const total = 300
	received := make(chan int, 1)
	go func() {
		count := 0
		for range taskItem.Events() {
			count++
			if count == total {
				received <- count
				return
			}
		}
	}()
	for index := 0; index < total; index++ {
		taskItem.Publish(Event{Type: "test", Message: "event"})
	}
	select {
	case count := <-received:
		if count != total {
			t.Fatalf("事件数量错误: %d", count)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("事件发布被阻塞或发生丢失")
	}
	taskItem.Complete()
}
