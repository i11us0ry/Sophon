package database

import (
	"context"
	"testing"
	"time"
)

func TestListProjectsWithCountsPageUsesStableCursor(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"project-1", "project-2", "project-3", "project-4", "project-5"} {
		if err := db.CreateProject(ctx, Project{
			ID:          id,
			OwnerUserID: "user-1",
			Name:        id,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	for _, item := range []struct {
		id         string
		projectID  string
		prompt     int
		completion int
		estimated  bool
	}{
		{id: "conv-p5-a", projectID: "project-5", prompt: 100, completion: 20},
		{id: "conv-p5-b", projectID: "project-5", prompt: 200, completion: 30, estimated: true},
		{id: "conv-p4-a", projectID: "project-4", prompt: 250, completion: 50},
	} {
		if err := db.CreateConversation(ctx, Conversation{
			ID: item.id, OwnerUserID: "user-1", ProjectID: item.projectID,
			Title: item.id, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("创建会话失败: %v", err)
		}
		if err := db.AddTokenUsage(ctx, TokenUsage{
			ID:               "usage-" + item.id,
			ConversationID:   item.id,
			UserID:           "user-1",
			MessageID:        "msg-" + item.id,
			PromptTokens:     item.prompt,
			CompletionTokens: item.completion,
			TotalTokens:      item.prompt + item.completion,
			Estimated:        item.estimated,
			Kind:             "chat",
			CreatedAt:        now,
		}); err != nil {
			t.Fatalf("写入 Token 用量失败: %v", err)
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO token_usage (
			id, conversation_id, project_id, user_id, message_id,
			prompt_tokens, completion_tokens, total_tokens, estimated,
			kind, model, created_at
		) VALUES ('usage-foreign', 'conv-p5-a', 'project-5', 'user-2', 'msg-foreign',
			10000, 10000, 20000, 0, 'chat', '', ?)`,
		now.Unix(),
	); err != nil {
		t.Fatalf("写入跨用户 Token 失败: %v", err)
	}

	first, hasMore, err := db.ListProjectsWithCountsPage(ctx, "user-1", 2, "")
	if err != nil {
		t.Fatalf("读取第一页失败: %v", err)
	}
	if !hasMore || len(first) != 2 || first[0].ID != "project-5" || first[1].ID != "project-4" {
		t.Fatalf("第一页异常: hasMore=%v projects=%+v", hasMore, first)
	}
	if first[0].Counts.PromptTokens != 300 ||
		first[0].Counts.CompletionTokens != 50 ||
		first[0].Counts.TotalTokens != 350 ||
		!first[0].Counts.TokenUsageEstimated {
		t.Fatalf("project-5 Token 汇总错误: %+v", first[0].Counts)
	}
	if first[1].Counts.TotalTokens != 300 || first[1].Counts.TokenUsageEstimated {
		t.Fatalf("project-4 Token 汇总错误: %+v", first[1].Counts)
	}
	summary, err := db.ProjectSummary(ctx, "project-5", "user-1")
	if err != nil || summary.TotalTokens != 350 || !summary.TokenUsageEstimated {
		t.Fatalf("项目详情 Token 汇总错误: %+v err=%v", summary, err)
	}

	second, hasMore, err := db.ListProjectsWithCountsPage(ctx, "user-1", 2, first[1].ID)
	if err != nil {
		t.Fatalf("读取第二页失败: %v", err)
	}
	if !hasMore || len(second) != 2 || second[0].ID != "project-3" || second[1].ID != "project-2" {
		t.Fatalf("第二页异常: hasMore=%v projects=%+v", hasMore, second)
	}

	last, hasMore, err := db.ListProjectsWithCountsPage(ctx, "user-1", 2, second[1].ID)
	if err != nil {
		t.Fatalf("读取最后一页失败: %v", err)
	}
	if hasMore || len(last) != 1 || last[0].ID != "project-1" {
		t.Fatalf("最后一页异常: hasMore=%v projects=%+v", hasMore, last)
	}
}

func TestListProjectsWithCountsOffsetFiltersAndPaginates(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, project := range []Project{
		{ID: "project-alpha", OwnerUserID: "user-1", Name: "Alpha", Status: "active"},
		{ID: "project-beta", OwnerUserID: "user-1", Name: "Beta", Status: "paused"},
		{ID: "project-gamma", OwnerUserID: "user-1", Name: "Gamma", Status: "active"},
		{ID: "project-delta", OwnerUserID: "user-1", Name: "Delta", Status: "archived"},
	} {
		project.CreatedAt = now
		project.UpdatedAt = now
		if err := db.CreateProject(ctx, project); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "vuln-beta", ProjectID: "project-beta", OwnerUserID: "user-1",
		Title: "Risk", Severity: "high", Status: "open",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建风险漏洞失败: %v", err)
	}

	items, total, stats, err := db.ListProjectsWithCountsOffset(ctx, ProjectListFilter{
		OwnerUserID: "user-1",
		Limit:       2,
	})
	if err != nil {
		t.Fatalf("读取项目分页失败: %v", err)
	}
	if total != 4 || len(items) != 2 {
		t.Fatalf("项目分页异常: total=%d items=%+v", total, items)
	}
	if stats.Total != 4 || stats.Active != 2 || stats.Paused != 1 || stats.Done != 0 || stats.Risk != 1 {
		t.Fatalf("项目统计异常: %+v", stats)
	}

	items, total, _, err = db.ListProjectsWithCountsOffset(ctx, ProjectListFilter{
		OwnerUserID: "user-1",
		Status:      "active",
		Limit:       20,
	})
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("项目状态筛选异常: total=%d items=%+v err=%v", total, items, err)
	}

	items, total, _, err = db.ListProjectsWithCountsOffset(ctx, ProjectListFilter{
		OwnerUserID: "user-1",
		Search:      "amm",
		Limit:       20,
	})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "project-gamma" {
		t.Fatalf("项目搜索筛选异常: total=%d items=%+v err=%v", total, items, err)
	}

	items, total, _, err = db.ListProjectsWithCountsOffset(ctx, ProjectListFilter{
		OwnerUserID: "user-1",
		RiskOnly:    true,
		Limit:       20,
	})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "project-beta" {
		t.Fatalf("项目风险筛选异常: total=%d items=%+v err=%v", total, items, err)
	}
}
