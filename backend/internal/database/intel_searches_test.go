package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestIntelSearchesPersistAndDeleteWithProject(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "intel-searches.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "intel-project",
		OwnerUserID: "user-1",
		Name:        "情报项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	record := IntelSearchRecord{
		ID:                 "search-1",
		OwnerUserID:        "user-1",
		ProjectID:          project.ID,
		Provider:           "fofa",
		Query:              `domain="example.com"`,
		Page:               1,
		PageSize:           20,
		ResultCount:        1,
		ResultsJSON:        `[{"url":"https://example.com"}]`,
		ProviderErrorsJSON: `[]`,
		CreatedAt:          now,
	}
	if err := db.CreateIntelSearch(ctx, record); err != nil {
		t.Fatalf("保存查询记录失败: %v", err)
	}
	items, total, err := db.ListIntelSearches(ctx, "user-1", project.ID, 20, 0)
	if err != nil {
		t.Fatalf("读取查询历史失败: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != record.ID {
		t.Fatalf("查询历史不符合预期: total=%d items=%+v", total, items)
	}
	if items[0].ResultsJSON != "" {
		t.Fatal("列表接口不应加载完整结果 JSON")
	}
	stored, err := db.GetIntelSearch(ctx, record.ID, "user-1")
	if err != nil {
		t.Fatalf("读取查询详情失败: %v", err)
	}
	if stored.ResultsJSON != record.ResultsJSON {
		t.Fatalf("查询结果不一致: %+v", stored)
	}
	if err := db.DeleteProject(ctx, project.ID, project.OwnerUserID); err != nil {
		t.Fatalf("删除项目失败: %v", err)
	}
	if _, err := db.GetIntelSearch(ctx, record.ID, "user-1"); !NoRows(err) {
		t.Fatalf("项目删除后查询历史应清理，实际 err=%v", err)
	}
}
