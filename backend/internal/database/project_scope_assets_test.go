package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestParseProjectScopeAssets(t *testing.T) {
	scope := `授权资产
*lenxin.com
*.example.com，*.example.net
https://n9e.oa.example.com/login
10.0.0.0/24
203.0.113.10 (oa 前端入口)`
	items := ParseProjectScopeAssets(scope)
	got := map[string]bool{}
	for _, item := range items {
		got[item.Value] = true
	}
	for _, want := range []string{
		"*.lenxin.com",
		"*.example.com",
		"*.example.net",
		"https://n9e.oa.example.com/login",
		"n9e.oa.example.com",
		"10.0.0.0/24",
		"203.0.113.10",
	} {
		if !got[want] {
			t.Fatalf("资产范围解析缺少 %s: %#v", want, items)
		}
	}
	if got["授权资产"] {
		t.Fatalf("标题行不应被当成资产: %#v", items)
	}
}

func TestSyncProjectScopeAssetsIsIdempotent(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-scope.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "scope-project",
		OwnerUserID: "user-1",
		Name:        "scope",
		Scope:       "*.example.com\n10.0.0.0/24\n203.0.113.10",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	first, err := db.SyncProjectScopeAssets(ctx, project.ID, project.OwnerUserID, project.Scope)
	if err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	if first.Created != 3 || first.Skipped != 0 {
		t.Fatalf("首次同步结果异常: %+v", first)
	}
	second, err := db.SyncProjectScopeAssets(ctx, project.ID, project.OwnerUserID, project.Scope)
	if err != nil {
		t.Fatalf("重复同步失败: %v", err)
	}
	if second.Created != 0 || second.Skipped != 3 {
		t.Fatalf("重复同步应全部跳过: %+v", second)
	}

	assets, err := db.ListProjectAssets(ctx, project.ID, project.OwnerUserID)
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("资产数量应为 3，实际 %d", len(assets))
	}
	kinds := map[string]string{}
	for _, asset := range assets {
		kinds[asset.Value] = asset.Kind
	}
	if kinds["*.example.com"] != "domain" {
		t.Fatalf("通配域名类型错误: %#v", kinds)
	}
	if kinds["10.0.0.0/24"] != "host" {
		t.Fatalf("CIDR 类型错误: %#v", kinds)
	}
	if kinds["203.0.113.10"] != "ip" {
		t.Fatalf("IP 类型错误: %#v", kinds)
	}
}

func TestBackfillProjectScopeAssets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-scope-backfill.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "legacy-scope-project",
		OwnerUserID: "user-1",
		Name:        "legacy",
		Scope:       "授权资产\n*.example.com\n*.example.net",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	// CreateProject 只负责项目本身，这里模拟升级前的历史数据，再执行回填。
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE project_id = ?`, project.ID); err != nil {
		t.Fatalf("清理资产失败: %v", err)
	}
	if err := db.backfillProjectScopeAssets(ctx); err != nil {
		t.Fatalf("回填资产失败: %v", err)
	}
	assets, err := db.ListProjectAssets(ctx, project.ID, project.OwnerUserID)
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("回填资产数量应为 2，实际 %d: %#v", len(assets), assets)
	}
}
