package database

import (
	"context"
	"testing"
)

func TestConversationHITLOverride(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-hitl", "审批测试")

	value, err := db.GetConversationHITLOverride(ctx, "conv-hitl")
	if err != nil {
		t.Fatalf("读取默认覆盖失败: %v", err)
	}
	if value != nil {
		t.Fatalf("未配置时应跟随全局设置: %v", *value)
	}

	if err := db.SetConversationHITLOverride(ctx, "conv-hitl", true); err != nil {
		t.Fatalf("开启会话审批失败: %v", err)
	}
	value, err = db.GetConversationHITLOverride(ctx, "conv-hitl")
	if err != nil || value == nil || !*value {
		t.Fatalf("会话审批应开启: value=%v err=%v", value, err)
	}

	if err := db.SetConversationHITLOverride(ctx, "conv-hitl", false); err != nil {
		t.Fatalf("关闭会话审批失败: %v", err)
	}
	value, err = db.GetConversationHITLOverride(ctx, "conv-hitl")
	if err != nil || value == nil || *value {
		t.Fatalf("会话审批应关闭: value=%v err=%v", value, err)
	}
}
