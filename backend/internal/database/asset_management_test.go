package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAssetDuplicateAndProjectMoveProtection(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-management.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, projectID := range []string{"asset-project-a", "asset-project-b"} {
		if err := db.CreateProject(ctx, Project{
			ID:          projectID,
			OwnerUserID: "user-1",
			Name:        projectID,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	asset := Asset{
		ID:          "asset-canonical",
		ProjectID:   "asset-project-a",
		OwnerUserID: "user-1",
		Name:        "主站",
		Kind:        "url",
		Value:       "https://example.com",
		Status:      "active",
		Criticality: "medium",
		RiskScore:   20,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}

	duplicate := asset
	duplicate.ID = "asset-duplicate"
	duplicate.Name = "重复资产"
	if err := db.CreateAsset(ctx, duplicate); !errors.Is(err, ErrAssetDuplicate) {
		t.Fatalf("重复资产应被拒绝，实际 %v", err)
	}

	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID:          "asset-linked-vulnerability",
		ProjectID:   asset.ProjectID,
		AssetID:     asset.ID,
		OwnerUserID: asset.OwnerUserID,
		Title:       "关联漏洞",
		Severity:    "high",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建关联漏洞失败: %v", err)
	}

	asset.ProjectID = "asset-project-b"
	asset.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateAsset(ctx, asset); !errors.Is(err, ErrAssetInUse) {
		t.Fatalf("被引用资产跨项目移动应被拒绝，实际 %v", err)
	}
}

func TestDeleteAssetClearsFactReferenceAndDoesNotRecreate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-delete-reference.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "asset-delete-project",
		OwnerUserID: "user-1",
		Name:        "资产删除引用",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	asset := Asset{
		ID:          "asset-delete-reference",
		ProjectID:   "asset-delete-project",
		OwnerUserID: "user-1",
		Name:        "目标",
		Kind:        "url",
		Value:       "https://example.com/target",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  asset.ProjectID,
		FactType:   "asset",
		Key:        "目标资产",
		Value:      asset.Name,
		Relation:   "asset_id:" + asset.ID,
		Confidence: 100,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}

	if err := db.DeleteAsset(ctx, asset.ID, asset.OwnerUserID); err != nil {
		t.Fatalf("删除资产失败: %v", err)
	}
	facts, err := db.ListProjectFacts(ctx, asset.ProjectID)
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 || facts[0].Relation != "" {
		t.Fatalf("删除资产后事实关系应清空: %+v", facts)
	}
	if err := db.backfillProjectAssets(ctx); err != nil {
		t.Fatalf("执行回填失败: %v", err)
	}
	assets, err := db.ListProjectAssets(ctx, asset.ProjectID, asset.OwnerUserID)
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("已删除资产不应因事实关系重新创建: %+v", assets)
	}
}

func TestAssetValidationRejectsInvalidEnumsAndValues(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	base := Asset{
		ID:          "asset-invalid",
		OwnerUserID: "user-1",
		Name:        "非法资产",
		Kind:        "url",
		Value:       "https://example.com",
		Status:      "invalid",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("非法状态应被拒绝，实际 %v", err)
	}
	base.Status = "active"
	base.RiskScore = 101
	if err := db.CreateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("非法风险分应被拒绝，实际 %v", err)
	}
}

func TestAssetValidationEnforcesSupportedKindsOnCreateAndUpdate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-kind-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	base := Asset{
		ID:          "asset-kind-url",
		OwnerUserID: "user-1",
		Name:        "合法资产",
		Kind:        "url",
		Value:       "https://example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	for _, kind := range []string{"ip", "domain", "url", "port", "host"} {
		item := base
		item.ID = "asset-kind-" + kind
		item.Name = "合法类型 " + kind
		item.Kind = kind
		item.Value = kind + "-value"
		if err := db.CreateAsset(context.Background(), item); err != nil {
			t.Fatalf("创建类型 %q 失败: %v", kind, err)
		}
	}

	for _, kind := range []string{"", "endpoint", "other", "service"} {
		item := base
		item.ID = "asset-kind-" + kind
		item.Name = "非法类型 " + kind
		item.Kind = kind
		if err := db.CreateAsset(context.Background(), item); !errors.Is(err, ErrInvalidAsset) {
			t.Fatalf("创建类型 %q 应被拒绝，实际 %v", kind, err)
		}
	}

	base.Kind = "port"
	base.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateAsset(context.Background(), base); err != nil {
		t.Fatalf("编辑为 port 失败: %v", err)
	}
	base.Kind = "host"
	base.UpdatedAt = now.Add(2 * time.Minute)
	if err := db.UpdateAsset(context.Background(), base); err != nil {
		t.Fatalf("编辑为 host 失败: %v", err)
	}
	base.Kind = "other"
	base.UpdatedAt = now.Add(3 * time.Minute)
	if err := db.UpdateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("编辑为非法类型应被拒绝，实际 %v", err)
	}
}

func TestListAssetsFiltered(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-filter.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, projectID := range []string{"filter-project-a", "filter-project-b"} {
		if err := db.CreateProject(ctx, Project{
			ID:          projectID,
			OwnerUserID: "user-1",
			Name:        projectID,
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	for _, item := range []Asset{
		{
			ID: "filter-a-url", ProjectID: "filter-project-a", OwnerUserID: "user-1",
			Name: "主站", Kind: "url", Value: "https://example.com",
			Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "filter-a-ip", ProjectID: "filter-project-a", OwnerUserID: "user-1",
			Name: "内网", Kind: "ip", Value: "10.0.0.1",
			Status: "inactive", Criticality: "low", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "filter-b-url", ProjectID: "filter-project-b", OwnerUserID: "user-1",
			Name: "其他主站", Kind: "url", Value: "https://other.example.com",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}

	items, total, err := db.ListAssetsFiltered(ctx, AssetFilter{
		OwnerUserID: "user-1",
		ProjectID:   "filter-project-a",
		Kind:        "url",
		Status:      "active",
		Search:      "example.com",
		Limit:       20,
	})
	if err != nil {
		t.Fatalf("筛选资产失败: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "filter-a-url" {
		t.Fatalf("资产筛选结果错误: total=%d items=%+v", total, items)
	}
}

func TestRepairFactAssetPrefersCanonicalOverGeneratedDuplicate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-relation-canonical.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "asset-relation-project",
		OwnerUserID: "user-1",
		Name:        "关系规范化",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	assets := []Asset{
		{
			ID: "asset-relation-canonical", ProjectID: "asset-relation-project",
			OwnerUserID: "user-1", Name: "Pikachu 页面", Kind: "url",
			Value: "https://example.com/pikachu", Status: "active",
			Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-relation-generated", ProjectID: "asset-relation-project",
			OwnerUserID: "user-1", Name: "Pikachu 页面", Kind: "other",
			Value: "Pikachu 页面", Status: "active",
			Criticality: "medium", CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute),
		},
	}
	for _, item := range assets {
		if item.Kind == "other" {
			if _, err := db.ExecContext(
				context.Background(),
				`INSERT INTO assets (
					id, project_id, owner_user_id, name, kind, value, status,
					criticality, risk_score, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				item.ID,
				item.ProjectID,
				item.OwnerUserID,
				item.Name,
				item.Kind,
				item.Value,
				item.Status,
				item.Criticality,
				item.RiskScore,
				item.CreatedAt.Unix(),
				item.UpdatedAt.Unix(),
			); err != nil {
				t.Fatalf("按历史数据写入资产失败: %v", err)
			}
			continue
		}
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	fact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  "asset-relation-project",
		FactType:   "asset",
		Key:        "Pikachu",
		Value:      "Pikachu 页面",
		Relation:   "asset:asset-relation-generated",
		Confidence: 100,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID:        newID(),
		ProjectID: "asset-relation-project",
		Kind:      "fact",
		Title:     fact.Key,
		Status:    "confirmed",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建事实节点失败: %v", err)
	}
	if err := db.backfillProjectAssets(ctx); err != nil {
		t.Fatalf("修复事实关系失败: %v", err)
	}
	facts, err := db.ListProjectFacts(ctx, "asset-relation-project")
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 || facts[0].Relation != "asset_id:asset-relation-canonical" {
		t.Fatalf("事实关系应优先指向正常资产: %+v", facts)
	}
	nodes, err := db.ListProjectGraphNodes(ctx, "asset-relation-project")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "fact" && node.AssetID != "asset-relation-canonical" {
			t.Fatalf("事实节点应指向正常资产: %+v", node)
		}
	}
}
