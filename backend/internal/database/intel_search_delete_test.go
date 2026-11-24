package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDeleteIntelSearchIsOwnerScoped(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "intel-search-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.CreateIntelSearch(ctx, IntelSearchRecord{
		ID:                 "search-delete",
		OwnerUserID:        "user-1",
		Provider:           "fofa",
		Query:              `domain="example.com"`,
		Page:               1,
		PageSize:           20,
		ResultsJSON:        `[]`,
		ProviderErrorsJSON: `[]`,
	}); err != nil {
		t.Fatalf("创建查询记录失败: %v", err)
	}
	if err := db.DeleteIntelSearch(ctx, "search-delete", "user-2"); !NoRows(err) {
		t.Fatalf("其他用户删除应返回不存在，实际 %v", err)
	}
	if err := db.DeleteIntelSearch(ctx, "search-delete", "user-1"); err != nil {
		t.Fatalf("删除查询记录失败: %v", err)
	}
	if _, err := db.GetIntelSearch(ctx, "search-delete", "user-1"); !NoRows(err) {
		t.Fatalf("记录应已删除，实际 %v", err)
	}
}
