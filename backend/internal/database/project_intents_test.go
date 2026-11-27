package database

import (
	"context"
	"testing"
	"time"
)

func TestListProjectIntentsPageFiltersAndExpiresDerived(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID: "project-intents-page", OwnerUserID: "user-1", Name: "intents",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	for _, node := range []GraphNode{
		{ID: "intent-open", ProjectID: project.ID, Kind: "intent", Title: "验证 SQL 注入", Status: "open", Confidence: 80, CreatedAt: now, UpdatedAt: now},
		{ID: "intent-blocked", ProjectID: project.ID, Kind: "intent", Title: "验证文件上传", Status: "blocked", Confidence: 60, CreatedAt: now, UpdatedAt: now},
		{ID: "intent-old", ProjectID: project.ID, Kind: "intent", Title: "旧派生路径", Status: "open", Source: "blocked-follow-up", CreatedAt: now.Add(-8 * 24 * time.Hour), UpdatedAt: now},
	} {
		if err := db.CreateProjectGraphNode(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID:      project.ID,
		Dimension:      "验证文件上传",
		Technique:      "upload",
		Status:         "blocked",
		StateReason:    "目标返回 403，需要授权会话",
		Result:         "无法继续未授权上传验证",
		Evidence:       "HTTP 403 + 响应正文",
		EvidenceRefs:   []string{"tool:upload-probe"},
		FindingID:      "finding-upload",
		IntentID:       "intent-blocked",
		Attempts:       2,
		LastFinishedAt: now,
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	items, total, err := db.ListProjectIntentsPage(ctx, ProjectIntentFilter{
		ProjectID: project.ID,
		Status:    "open",
		Query:     "sql",
		Limit:     20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "intent-open" {
		t.Fatalf("意图分页过滤错误: total=%d items=%+v", total, items)
	}
	blockedItems, blockedTotal, err := db.ListProjectIntentsPage(ctx, ProjectIntentFilter{
		ProjectID: project.ID,
		Status:    "blocked",
		Limit:     20,
	})
	if err != nil || blockedTotal != 1 || len(blockedItems) != 1 {
		t.Fatalf("已完成意图查询失败: total=%d items=%+v err=%v", blockedTotal, blockedItems, err)
	}
	blocked := blockedItems[0]
	if blocked.Result != "无法继续未授权上传验证" ||
		blocked.StateReason != "目标返回 403，需要授权会话" ||
		blocked.Evidence != "HTTP 403 + 响应正文" ||
		len(blocked.EvidenceRefs) != 1 ||
		blocked.FindingID != "finding-upload" ||
		blocked.Attempts != 2 ||
		!blocked.LastFinishedAt.Equal(now.Truncate(time.Second)) {
		t.Fatalf("意图完成结论未正确返回: %+v", blocked)
	}
	expired, err := db.expireDerivedProjectIntents(ctx, project.ID, now)
	if err != nil || expired != 1 {
		t.Fatalf("派生意图应过期: expired=%d err=%v", expired, err)
	}
	old, err := db.GetProjectGraphNode(ctx, "intent-old", project.ID)
	if err != nil || old.Status != "stopped" {
		t.Fatalf("旧派生意图状态错误: %+v err=%v", old, err)
	}
}
