package database

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestContextMetricsAggregates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "context-metrics.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-metrics",
		OwnerUserID: "user-1",
		Name:        "指标测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID:          "conv-metrics",
		OwnerUserID: "user-1",
		Title:       "指标",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	compactions := []ContextCompaction{
		{
			ID: "comp-1", ConversationID: "conv-metrics",
			TokensBefore: 1000, TokensAfter: 500, SummaryTokens: 120,
			Kind: "minor", Model: "test", LatencyMs: 800, CreatedAt: now,
		},
		{
			ID: "comp-2", ConversationID: "conv-metrics",
			TokensBefore: 1000, TokensAfter: 700, SummaryTokens: 200,
			Kind: "major", Model: "test", LatencyMs: 1200, CreatedAt: now.Add(time.Minute),
		},
	}
	for _, item := range compactions {
		if err := db.AddContextCompaction(ctx, item); err != nil {
			t.Fatalf("写入压缩记录失败: %v", err)
		}
	}
	writes := []MemoryWrite{
		{ID: "w1", ProjectID: "project-metrics", FactID: "f1", Action: "ADD", CreatedAt: now},
		{ID: "w2", ProjectID: "project-metrics", FactID: "f1", Action: "UPDATE", CreatedAt: now},
		{ID: "w3", ProjectID: "project-metrics", FactID: "f2", Action: "NONE", CreatedAt: now},
		{ID: "w4", ProjectID: "project-metrics", FactID: "f3", Action: "SUPERSEDE", CreatedAt: now},
	}
	for _, item := range writes {
		if err := db.AddMemoryWrite(ctx, item); err != nil {
			t.Fatalf("写入记忆审计失败: %v", err)
		}
	}
	if err := db.AddInjectionEvent(ctx, InjectionEvent{
		ID: "inj-1", ConversationID: "conv-metrics", ProjectID: "project-metrics",
		SourceType: "fact", SourceID: "目标IP", Patterns: "ignore-instructions",
		Action: "tainted", CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入注入事件失败: %v", err)
	}

	metrics, err := db.ContextMetrics(ctx, "user-1", false)
	if err != nil {
		t.Fatalf("读取指标失败: %v", err)
	}
	if metrics.Compactions != 2 || metrics.CompactionsMinor != 1 || metrics.CompactionsMajor != 1 {
		t.Fatalf("压缩计数错误: %+v", metrics)
	}
	if expected := 0.6; math.Abs(metrics.AvgRatio-expected) > 1e-6 {
		t.Fatalf("平均压缩比应为 %.2f，实际 %.4f", expected, metrics.AvgRatio)
	}
	if metrics.MemoryTotal != 4 || metrics.MemoryAdd != 1 || metrics.MemorySupersede != 1 {
		t.Fatalf("记忆写入统计错误: %+v", metrics)
	}
	if metrics.Injections != 1 {
		t.Fatalf("注入事件统计错误: %+v", metrics)
	}

	items, err := db.ListContextCompactionsForUser(ctx, "user-1", "conv-metrics", 10, false)
	if err != nil {
		t.Fatalf("读取压缩列表失败: %v", err)
	}
	if len(items) != 2 || items[0].Kind != "major" {
		t.Fatalf("压缩列表应按时间倒序返回 kind: %+v", items)
	}
	if _, err := db.ListContextCompactionsForUser(ctx, "user-2", "", 10, false); err != nil {
		t.Fatalf("其他用户查询不应报错: %v", err)
	}

	// 管理员全局范围可以看到归属其他用户的记录与记忆统计。
	allMetrics, err := db.ContextMetrics(ctx, "user-2", true)
	if err != nil {
		t.Fatalf("全局指标查询失败: %v", err)
	}
	if allMetrics.Compactions != 2 || allMetrics.MemoryTotal != 4 {
		t.Fatalf("全局指标应包含所有用户数据: %+v", allMetrics)
	}
	if allMetrics.Injections != 1 {
		t.Fatalf("全局注入统计错误: %+v", allMetrics)
	}
	allItems, err := db.ListContextCompactionsForUser(ctx, "user-2", "", 10, true)
	if err != nil {
		t.Fatalf("全局压缩列表查询失败: %v", err)
	}
	if len(allItems) != 2 {
		t.Fatalf("全局压缩列表应返回 2 条，实际 %d", len(allItems))
	}
}
