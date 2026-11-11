package database

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGetMessagePageUsesStableCursor(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-page", "分页测试")
	for _, id := range []string{"msg-1", "msg-2", "msg-3", "msg-4", "msg-5"} {
		addTestMessage(t, db, id, "conv-page", "user", id)
	}

	first, hasMore, err := db.GetMessagePage(ctx, "conv-page", "", 2)
	if err != nil {
		t.Fatalf("读取第一页失败: %v", err)
	}
	if !hasMore || len(first) != 2 || first[0].ID != "msg-4" || first[1].ID != "msg-5" {
		t.Fatalf("第一页异常: hasMore=%v messages=%+v", hasMore, first)
	}

	second, hasMore, err := db.GetMessagePage(ctx, "conv-page", first[0].ID, 2)
	if err != nil {
		t.Fatalf("读取第二页失败: %v", err)
	}
	if !hasMore || len(second) != 2 || second[0].ID != "msg-2" || second[1].ID != "msg-3" {
		t.Fatalf("第二页异常: hasMore=%v messages=%+v", hasMore, second)
	}

	last, hasMore, err := db.GetMessagePage(ctx, "conv-page", second[0].ID, 2)
	if err != nil {
		t.Fatalf("读取最后一页失败: %v", err)
	}
	if hasMore || len(last) != 1 || last[0].ID != "msg-1" {
		t.Fatalf("最后一页异常: hasMore=%v messages=%+v", hasMore, last)
	}
}

func TestGetMessagePageAfterUsesStableCursor(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-page-after", "向下分页测试")
	for _, id := range []string{"msg-1", "msg-2", "msg-3", "msg-4", "msg-5"} {
		addTestMessage(t, db, id, "conv-page-after", "user", id)
	}

	first, hasMore, err := db.GetMessagePageAfter(ctx, "conv-page-after", "msg-1", 2)
	if err != nil {
		t.Fatalf("读取向下一页失败: %v", err)
	}
	if !hasMore || len(first) != 2 || first[0].ID != "msg-2" || first[1].ID != "msg-3" {
		t.Fatalf("向下一页异常: hasMore=%v messages=%+v", hasMore, first)
	}

	second, hasMore, err := db.GetMessagePageAfter(ctx, "conv-page-after", "msg-3", 2)
	if err != nil {
		t.Fatalf("读取向下一二页失败: %v", err)
	}
	if hasMore || len(second) != 2 || second[0].ID != "msg-4" || second[1].ID != "msg-5" {
		t.Fatalf("向下一二页异常: hasMore=%v messages=%+v", hasMore, second)
	}
}

func TestListConversationsPageUsesStableCursor(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	for _, id := range []string{"conv-1", "conv-2", "conv-3", "conv-4", "conv-5"} {
		addTestConversation(t, db, id, id)
	}

	first, hasMore, err := db.ListConversationsPage(ctx, "user-1", 2, "")
	if err != nil {
		t.Fatalf("读取第一页失败: %v", err)
	}
	if !hasMore || len(first) != 2 || first[0].ID != "conv-5" || first[1].ID != "conv-4" {
		t.Fatalf("第一页异常: hasMore=%v conversations=%+v", hasMore, first)
	}

	second, hasMore, err := db.ListConversationsPage(ctx, "user-1", 2, first[1].ID)
	if err != nil {
		t.Fatalf("读取第二页失败: %v", err)
	}
	if !hasMore || len(second) != 2 || second[0].ID != "conv-3" || second[1].ID != "conv-2" {
		t.Fatalf("第二页异常: hasMore=%v conversations=%+v", hasMore, second)
	}

	last, hasMore, err := db.ListConversationsPage(ctx, "user-1", 2, second[1].ID)
	if err != nil {
		t.Fatalf("读取最后一页失败: %v", err)
	}
	if hasMore || len(last) != 1 || last[0].ID != "conv-1" {
		t.Fatalf("最后一页异常: hasMore=%v conversations=%+v", hasMore, last)
	}
}

func TestListConversationsPageIncludesLatestUserMessagePreview(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-preview", "预览测试")
	addTestMessage(t, db, "msg-preview-user-old", "conv-preview", "user", "旧问题")
	time.Sleep(2 * time.Millisecond)
	addTestMessage(t, db, "msg-preview-assistant", "conv-preview", "assistant", "助手回答")
	time.Sleep(2 * time.Millisecond)
	latestQuestion := strings.Repeat("新问题", 120)
	addTestMessage(t, db, "msg-preview-user-new", "conv-preview", "user", latestQuestion)

	items, _, err := db.ListConversationsPage(ctx, "user-1", 10, "")
	if err != nil {
		t.Fatalf("读取会话列表失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("会话数量错误: %+v", items)
	}
	if len([]rune(items[0].LastUserMessage)) != 300 ||
		!strings.HasPrefix(items[0].LastUserMessage, "新问题") ||
		strings.Contains(items[0].LastUserMessage, "助手回答") {
		t.Fatalf("最后用户消息预览错误: %q", items[0].LastUserMessage)
	}
}

func TestListProcessDetailsByMessageIDs(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-details", "详情测试")
	for _, item := range []struct {
		id        string
		messageID string
	}{
		{id: "pd-1", messageID: "msg-1"},
		{id: "pd-2", messageID: "msg-2"},
		{id: "pd-3", messageID: "msg-3"},
	} {
		if err := db.AddProcessDetail(ctx, ProcessDetail{
			ID:             item.id,
			ConversationID: "conv-details",
			MessageID:      item.messageID,
			EventType:      "tool_result",
			Message:        "exec",
			Data:           map[string]interface{}{"result": item.id},
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			t.Fatalf("写入过程明细失败: %v", err)
		}
	}

	details, err := db.ListProcessDetailsByMessageIDs(
		ctx,
		"conv-details",
		[]string{"msg-1", "msg-3", "msg-1"},
	)
	if err != nil {
		t.Fatalf("按消息读取过程明细失败: %v", err)
	}
	if len(details) != 2 || details[0].ID != "pd-1" || details[1].ID != "pd-3" {
		t.Fatalf("过程明细筛选异常: %+v", details)
	}

	recent, err := db.ListProcessDetails(ctx, "conv-details", 2)
	if err != nil {
		t.Fatalf("读取最近过程明细失败: %v", err)
	}
	if len(recent) != 2 || recent[0].ID != "pd-2" || recent[1].ID != "pd-3" {
		t.Fatalf("最近过程明细应保留最新两条: %+v", recent)
	}
}

func TestListAgentLifecycleDetailsIgnoresProcessPage(e *testing.T) {
	db := openConversationTestDB(e)
	ctx := context.Background()
	addTestConversation(e, db, "conv-lifecycle", "生命周期测试")
	now := time.Now().UTC()
	for _, item := range []struct {
		id        string
		messageID string
		eventType string
		agentID   string
	}{
		{id: "lifecycle-1", messageID: "msg-lifecycle", eventType: "subagent.started", agentID: "worker-1"},
		{id: "lifecycle-2", messageID: "msg-lifecycle", eventType: "subagent.completed", agentID: "worker-1"},
		{id: "lifecycle-other", messageID: "msg-other", eventType: "subagent.started", agentID: "worker-2"},
	} {
		if err := db.AddProcessDetail(ctx, ProcessDetail{
			ID:             item.id,
			ConversationID: "conv-lifecycle",
			MessageID:      item.messageID,
			EventType:      item.eventType,
			Message:        item.eventType,
			Data: map[string]interface{}{
				"agentId": item.agentID, "agentKind": "worker", "agentName": item.agentID,
			},
			CreatedAt: now,
		}); err != nil {
			e.Fatalf("写入生命周期失败: %v", err)
		}
	}
	for index := 0; index < 250; index++ {
		if err := db.AddProcessDetail(ctx, ProcessDetail{
			ID:             "tool-" + strconv.Itoa(index),
			ConversationID: "conv-lifecycle",
			MessageID:      "msg-lifecycle",
			EventType:      "tool_result",
			Message:        "exec",
			Data:           map[string]interface{}{"result": "ok"},
			CreatedAt:      now.Add(time.Duration(index) * time.Millisecond),
		}); err != nil {
			e.Fatalf("写入工具过程失败: %v", err)
		}
	}
	details, err := db.ListAgentLifecycleDetails(ctx, "conv-lifecycle", []string{"msg-lifecycle"})
	if err != nil {
		e.Fatalf("读取生命周期失败: %v", err)
	}
	if len(details) != 2 || details[0].ID != "lifecycle-1" || details[1].ID != "lifecycle-2" {
		e.Fatalf("生命周期不应受过程分页裁剪: %+v", details)
	}
}
