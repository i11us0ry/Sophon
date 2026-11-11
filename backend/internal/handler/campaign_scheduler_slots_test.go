package handler

import (
	"context"
	"testing"
	"time"

	"sophon/internal/task"
)

func TestCampaignUserRunSlotsLimitToFive(t *testing.T) {
	scheduler := NewCampaignScheduler(nil, &ChatHandler{
		manager: task.NewManagerWithLimit(5),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acquired := make(chan int, 6)
	for index := 0; index < 6; index++ {
		go func(index int) {
			if scheduler.acquireUserRunSlot(ctx, "user-1") {
				acquired <- index
			}
		}(index)
	}
	for index := 0; index < 5; index++ {
		select {
		case <-acquired:
		case <-time.After(time.Second):
			t.Fatalf("前 5 个运行槽位未全部获取")
		}
	}
	select {
	case index := <-acquired:
		t.Fatalf("第 6 个任务不应运行，实际获取槽位 %d", index)
	case <-time.After(100 * time.Millisecond):
	}

	scheduler.releaseUserRunSlot("user-1")
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatalf("释放槽位后排队任务未启动")
	}
}

func TestTaskManagerDefaultConcurrencyIsFive(t *testing.T) {
	if got := task.NewManager().MaxPerUser(); got != 5 {
		t.Fatalf("默认单用户并发上限应为 5，实际 %d", got)
	}
}
