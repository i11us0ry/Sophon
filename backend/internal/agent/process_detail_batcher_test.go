package agent

import (
	"context"
	"testing"
	"time"
)

func TestProcessDetailBatcherClosesAndFlushesInOrder(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	batcher := newProcessDetailBatcherWithConfig(service.db, 100, 1024, time.Hour)
	batchCtx := withProcessDetailBatcher(ctx, batcher)

	for index := 0; index < 3; index++ {
		event := Event{
			Type:    "custom",
			Message: "event-" + string(rune('1'+index)),
			Data:    map[string]interface{}{"index": index},
		}
		if err := service.persistEvent(batchCtx, usage.conversationID, usage.messageID, event); err != nil {
			t.Fatalf("写入 batcher 失败: %v", err)
		}
	}
	if details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10); err != nil || len(details) != 0 {
		t.Fatalf("关闭前不应强制同步写入: %+v err=%v", details, err)
	}
	if err := batcher.Close(context.Background()); err != nil {
		t.Fatalf("关闭 batcher 失败: %v", err)
	}
	details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
	if err != nil || len(details) != 3 {
		t.Fatalf("关闭后应完整落库: %+v err=%v", details, err)
	}
	for index, detail := range details {
		if detail.Data["index"] != float64(index) {
			t.Fatalf("过程明细顺序错误: %+v", details)
		}
	}
}

func TestProcessDetailBatcherOverflowFlushesImmediately(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	batcher := newProcessDetailBatcherWithConfig(service.db, 100, 3, time.Hour)
	batchCtx := withProcessDetailBatcher(ctx, batcher)
	for index := 0; index < 3; index++ {
		if err := service.persistEvent(batchCtx, usage.conversationID, usage.messageID, Event{
			Type:    "custom",
			Message: "overflow",
			Data:    map[string]interface{}{"index": index},
		}); err != nil {
			t.Fatalf("溢出写入失败: %v", err)
		}
	}
	details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
	if err != nil || len(details) != 3 {
		t.Fatalf("达到 pending 上限后应立即 flush: %+v err=%v", details, err)
	}
	if err := batcher.Close(context.Background()); err != nil {
		t.Fatalf("关闭 batcher 失败: %v", err)
	}
}

func TestProcessDetailBatcherCloseWorksAfterContextCancel(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	batcher := newProcessDetailBatcherWithConfig(service.db, 100, 1024, time.Hour)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	batchCtx := withProcessDetailBatcher(canceled, batcher)
	if err := service.persistEvent(batchCtx, usage.conversationID, usage.messageID, Event{
		Type:    "custom",
		Message: "canceled-run",
	}); err != nil {
		t.Fatalf("取消态入队失败: %v", err)
	}
	if err := batcher.Close(canceled); err != nil {
		t.Fatalf("取消态关闭 flush 失败: %v", err)
	}
	details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
	if err != nil || len(details) != 1 {
		t.Fatalf("取消后最终 flush 丢数据: %+v err=%v", details, err)
	}
}

func TestProcessDetailBatcherPeriodicFlush(t *testing.T) {
	service, usage, ctx := newConsumeTestEnv(t)
	batcher := newProcessDetailBatcherWithConfig(service.db, 64, 1024, 20*time.Millisecond)
	batchCtx := withProcessDetailBatcher(ctx, batcher)
	if err := service.persistEvent(batchCtx, usage.conversationID, usage.messageID, Event{
		Type:    "custom",
		Message: "periodic",
	}); err != nil {
		t.Fatalf("周期写入失败: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		details, err := service.db.ListProcessDetails(ctx, usage.conversationID, 10)
		if err == nil && len(details) == 1 {
			if err := batcher.Close(context.Background()); err != nil {
				t.Fatalf("关闭 batcher 失败: %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = batcher.Close(context.Background())
	t.Fatal("周期 flush 未落库")
}
