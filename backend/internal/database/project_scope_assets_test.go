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
	if got["n9e.oa.example.com"] {
		t.Fatalf("URL 不应自动派生 Host 顶层资产: %#v", items)
	}
}

func TestMarkProjectScopeDerivedAssetsAndHideFromOverview(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-scope-derived.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "scope-derived-project",
		OwnerUserID: "user-1",
		Name:        "派生资产",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []Asset{
		{
			ID: "scope-url", ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
			Name: "https://portal.example.com", Kind: "url", Value: "https://portal.example.com",
			Status: "active", Source: AssetSourceScope, Criticality: "medium",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "scope-domain", ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
			Name: "https://portal.example.com", Kind: "domain", Value: "portal.example.com",
			Status: "active", Source: AssetSourceScope, Criticality: "medium",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "scope-ip", ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
			Name: "https://198.51.100.10:8443", Kind: "ip", Value: "198.51.100.10",
			Status: "active", Source: AssetSourceScope, Criticality: "medium",
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "scope-ip-url", ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
			Name: "https://198.51.100.10:8443", Kind: "url", Value: "https://198.51.100.10:8443",
			Status: "active", Source: AssetSourceScope, Criticality: "medium",
			CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产 %s 失败: %v", item.ID, err)
		}
	}
	if err := db.markProjectScopeDerivedAssets(ctx); err != nil {
		t.Fatalf("标记派生资产失败: %v", err)
	}
	for _, id := range []string{"scope-domain", "scope-ip"} {
		asset, err := db.GetAsset(ctx, id, project.OwnerUserID)
		if err != nil {
			t.Fatalf("读取派生资产 %s 失败: %v", id, err)
		}
		if asset.QualityStatus != AssetQualityCrossTypeDuplicate {
			t.Fatalf("派生资产 %s 质量状态错误: %s", id, asset.QualityStatus)
		}
	}
	items, total, err := db.ListProjectAssetOverview(
		ctx,
		project.ID,
		project.OwnerUserID,
		AssetOverviewFilter{State: "all", Limit: 20},
	)
	if err != nil {
		t.Fatalf("读取资产总览失败: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("默认总览应只显示两个 URL 资产，实际 total=%d items=%+v", total, items)
	}
	derived, derivedTotal, err := db.ListProjectAssetOverview(
		ctx,
		project.ID,
		project.OwnerUserID,
		AssetOverviewFilter{
			State:         "all",
			QualityStatus: AssetQualityCrossTypeDuplicate,
			Limit:         20,
		},
	)
	if err != nil {
		t.Fatalf("读取派生产物筛选失败: %v", err)
	}
	if derivedTotal != 2 || len(derived) != 2 {
		t.Fatalf("显式筛选应保留派生资产，实际 total=%d items=%+v", derivedTotal, derived)
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
	if kinds["10.0.0.0/24"] != "ip" {
		t.Fatalf("CIDR 类型错误: %#v", kinds)
	}
	if kinds["203.0.113.10"] != "ip" {
		t.Fatalf("IP 类型错误: %#v", kinds)
	}
	for _, asset := range assets {
		if asset.Source != AssetSourceScope {
			t.Fatalf("授权范围转换资产来源错误: %+v", asset)
		}
	}
}

func TestInferAssetKindSkipsAmbiguousBareArtifactName(t *testing.T) {
	if kind := inferAssetKind("seeyon20250422"); kind != "" {
		t.Fatalf("裸源码包名称不应自动推断为网络资产: %s", kind)
	}
	if kind := inferAssetKind("internal-host"); kind != "" {
		t.Fatalf("无点号且无端口的主机名应要求显式指定类型: %s", kind)
	}
	if kind := inferAssetKind("443"); kind != "" {
		t.Fatalf("纯端口值不应再被推断为资产: %s", kind)
	}
	if kind := inferAssetKind("app.internal"); kind != "domain" {
		t.Fatalf("带点号的内部主机名应推断为 domain: %s", kind)
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
