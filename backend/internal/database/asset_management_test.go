package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
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

func TestAssetSourceDefaultsAndCannotBeChangedByAssetUpdate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-source.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "asset-source-project", OwnerUserID: "user-1", Name: "资产来源",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	item := Asset{
		ID: "asset-source", ProjectID: "asset-source-project", OwnerUserID: "user-1",
		Name: "来源测试", Kind: "url", Value: "https://source.example.com",
		Status: "active", Source: AssetSourceManual, Criticality: "medium",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(ctx, item); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	stored, err := db.GetAsset(ctx, item.ID, item.OwnerUserID)
	if err != nil || stored.Source != AssetSourceManual {
		t.Fatalf("资产来源未持久化: %+v err=%v", stored, err)
	}

	item.Name = "来源不可改写"
	item.Source = AssetSourceHunter
	item.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateAsset(ctx, item); err != nil {
		t.Fatalf("更新资产失败: %v", err)
	}
	stored, err = db.GetAsset(ctx, item.ID, item.OwnerUserID)
	if err != nil || stored.Source != AssetSourceManual {
		t.Fatalf("资产编辑不应改写来源: %+v err=%v", stored, err)
	}

	if got := NormalizeAssetSource("fofa,hunter"); got != AssetSourceFOFAHunter {
		t.Fatalf("组合情报来源规范化错误: %s", got)
	}
	if got := NormalizeAssetSource(""); got != AssetSourceUnknown {
		t.Fatalf("空来源应回退为历史/未知: %s", got)
	}
}

func TestOpenMigratesLegacyAssetsToUnknownSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-asset-source.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("打开旧数据库失败: %v", err)
	}
	now := time.Now().UTC().Unix()
	if _, err := legacy.Exec(`
		CREATE TABLE assets (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL DEFAULT '',
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			value TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'unknown',
			criticality TEXT NOT NULL DEFAULT 'medium',
			risk_score INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);
		INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, status,
			criticality, risk_score, created_at, updated_at
		) VALUES (
			'asset-legacy-source', '', 'user-1', '历史资产',
			'domain', 'legacy.example.com', 'active', 'medium', 0, ?, ?
		)
	`, now, now); err != nil {
		_ = legacy.Close()
		t.Fatalf("创建旧资产表失败: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧数据库失败: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("迁移旧数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	asset, err := db.GetAsset(context.Background(), "asset-legacy-source", "user-1")
	if err != nil {
		t.Fatalf("读取迁移后的资产失败: %v", err)
	}
	if asset.Source != AssetSourceUnknown {
		t.Fatalf("旧资产来源应迁移为历史/未知: %+v", asset)
	}
}

func TestDeleteAssetRemovesOwnedDataAndDoesNotRecreate(t *testing.T) {
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
	otherAsset := Asset{
		ID: "asset-delete-other", ProjectID: asset.ProjectID, OwnerUserID: asset.OwnerUserID,
		Name: "保留资产", Kind: "url", Value: "https://example.com/keep",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(ctx, otherAsset); err != nil {
		t.Fatalf("创建其他资产失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conversation-delete-reference", OwnerUserID: asset.OwnerUserID,
		ProjectID: asset.ProjectID, AssetID: asset.ID, Title: "关联会话",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建关联会话失败: %v", err)
	}
	fact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  asset.ProjectID,
		AssetID:    asset.ID,
		FactType:   "asset",
		Key:        "目标资产",
		Value:      asset.Name,
		Relation:   "asset_id:" + asset.ID,
		Confidence: 100,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	otherFact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  otherAsset.ProjectID,
		AssetID:    otherAsset.ID,
		FactType:   "asset",
		Key:        "其他资产同名事实",
		Value:      otherAsset.Name,
		Relation:   "asset:" + asset.Name,
		Confidence: 100,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("创建其他资产事实失败: %v", err)
	}
	if _, err := db.UpsertProjectMemoryEntity(ctx, ProjectMemoryEntity{
		ID:          "memory-delete-reference",
		ProjectID:   asset.ProjectID,
		EntityType:  "asset",
		EntityKey:   asset.ID,
		Label:       asset.Name,
		SourceRefID: fact.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建记忆实体失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "vuln-delete-reference", ProjectID: asset.ProjectID, OwnerUserID: asset.OwnerUserID,
		AssetID: asset.ID, Title: "关联漏洞", Severity: "high", Status: "open",
		Fingerprint: "vuln-delete-fingerprint",
		CreatedAt:   now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建关联漏洞失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: "intent-delete-reference", ProjectID: asset.ProjectID, Kind: "intent",
		Title: "关联意图", Status: "open", AssetID: asset.ID, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建关联意图失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: "begin-delete-reference", ProjectID: asset.ProjectID, Kind: "begin",
		Title: "删除测试起点", Status: "open", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建起点失败: %v", err)
	}
	if err := db.CreateProjectGraphEdge(ctx, GraphEdge{
		ID: "edge-delete-reference", ProjectID: asset.ProjectID,
		SrcID: "begin-delete-reference", DstID: "intent-delete-reference",
		Rel: "spawns", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建关联边失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ID: "test-delete-reference", ProjectID: asset.ProjectID, AssetID: asset.ID,
		Dimension: "关联测试", Technique: "http", Status: "untested",
		IntentID: "intent-delete-reference", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建关联测试失败: %v", err)
	}
	if err := db.SyncProjectAssetWork(ctx, asset.ProjectID, asset.OwnerUserID); err != nil {
		t.Fatalf("同步资产工作项失败: %v", err)
	}

	impact, err := db.AssetDeleteImpact(ctx, asset.ID, asset.OwnerUserID)
	if err != nil {
		t.Fatalf("读取删除影响失败: %v", err)
	}
	if impact.Intents != 1 || impact.Facts != 1 || impact.Findings != 1 ||
		impact.Tests != 1 || impact.MemoryEntities != 1 {
		t.Fatalf("删除影响统计不准确: %+v", impact)
	}
	deleted, err := db.DeleteAsset(ctx, asset.ID, asset.OwnerUserID)
	if err != nil {
		t.Fatalf("删除资产失败: %v", err)
	}
	if deleted.Intents != impact.Intents || deleted.Facts != impact.Facts ||
		deleted.Findings != impact.Findings || deleted.Tests != impact.Tests {
		t.Fatalf("实际删除统计与预览不一致: preview=%+v actual=%+v", impact, deleted)
	}
	facts, err := db.ListProjectFacts(ctx, asset.ProjectID)
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 || facts[0].ID != otherFact.ID {
		t.Fatalf("删除资产后只应保留其他资产事实: %+v", facts)
	}
	var graphNodes int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = ? AND asset_id = ?`,
		asset.ProjectID,
		asset.ID,
	).Scan(&graphNodes); err != nil {
		t.Fatalf("统计攻击路径节点失败: %v", err)
	}
	if graphNodes != 0 {
		t.Fatalf("删除资产后关联意图节点应全部删除: %d", graphNodes)
	}
	var graphEdges int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_edges WHERE id = 'edge-delete-reference'`,
	).Scan(&graphEdges); err != nil {
		t.Fatalf("统计攻击路径边失败: %v", err)
	}
	if graphEdges != 0 {
		t.Fatalf("删除资产后关联攻击路径边应删除")
	}
	if vulnerability, err := db.GetVulnerability(ctx, "vuln-delete-reference", asset.OwnerUserID); !errors.Is(err, sql.ErrNoRows) || vulnerability != nil {
		t.Fatalf("删除资产后关联漏洞应删除: %+v err=%v", vulnerability, err)
	}
	var fingerprints int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM vulnerability_fingerprints WHERE project_id = ? AND vulnerability_id = 'vuln-delete-reference'`,
		asset.ProjectID,
	).Scan(&fingerprints); err != nil {
		t.Fatalf("统计漏洞指纹失败: %v", err)
	}
	if fingerprints != 0 {
		t.Fatalf("删除资产后漏洞指纹应删除")
	}
	var memoryEntities int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_memory_entities WHERE project_id = ? AND id = 'memory-delete-reference'`,
		asset.ProjectID,
	).Scan(&memoryEntities); err != nil {
		t.Fatalf("统计记忆实体失败: %v", err)
	}
	if memoryEntities != 0 {
		t.Fatalf("删除资产后记忆实体应删除")
	}
	var auditDetail string
	if err := db.QueryRowContext(
		ctx,
		`SELECT detail FROM audit_logs WHERE action = 'asset.delete_cascade' AND resource_id = ? ORDER BY created_at DESC LIMIT 1`,
		asset.ID,
	).Scan(&auditDetail); err != nil {
		t.Fatalf("读取删除审计失败: %v", err)
	}
	if !strings.Contains(auditDetail, "intents=1") || !strings.Contains(auditDetail, "facts=1") {
		t.Fatalf("删除审计统计缺失: %q", auditDetail)
	}
	testResults, err := db.ListProjectTestResultsByAsset(ctx, asset.ProjectID, asset.ID, 10)
	if err != nil || len(testResults) != 0 {
		t.Fatalf("删除资产后关联测试应删除: %+v err=%v", testResults, err)
	}
	work, err := db.GetProjectAssetWork(ctx, asset.ProjectID, asset.OwnerUserID, asset.ID)
	if err != nil || work != nil {
		t.Fatalf("删除资产后资产工作项应删除: %+v err=%v", work, err)
	}
	conversation, err := db.GetConversation(ctx, "conversation-delete-reference", asset.OwnerUserID)
	if err != nil || conversation == nil || conversation.AssetID != "" {
		t.Fatalf("删除资产后会话应保留并解除资产绑定: %+v err=%v", conversation, err)
	}
	if err := db.backfillProjectAssets(ctx); err != nil {
		t.Fatalf("执行回填失败: %v", err)
	}
	assets, err := db.ListProjectAssets(ctx, asset.ProjectID, asset.OwnerUserID)
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 1 || assets[0].ID != otherAsset.ID {
		t.Fatalf("只应保留其他资产且已删除资产不应重建: %+v", assets)
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

	validValues := map[string]string{
		"ip":     "10.0.0.1",
		"domain": "example.com",
		"url":    "https://example.com/path",
		"source": "seeyon20250422",
	}
	for _, kind := range []string{"ip", "domain", "url", "source"} {
		item := base
		item.ID = "asset-kind-" + kind
		item.Name = "合法类型 " + kind
		item.Kind = kind
		item.Value = validValues[kind]
		if err := db.CreateAsset(context.Background(), item); err != nil {
			t.Fatalf("创建类型 %q 失败: %v", kind, err)
		}
	}

	for _, kind := range []string{"", "endpoint", "host", "other", "service", "port"} {
		item := base
		item.ID = "asset-kind-" + kind
		item.Name = "非法类型 " + kind
		item.Kind = kind
		if err := db.CreateAsset(context.Background(), item); !errors.Is(err, ErrInvalidAsset) {
			t.Fatalf("创建类型 %q 应被拒绝，实际 %v", kind, err)
		}
	}

	base.Kind = "port"
	base.Value = "8443"
	base.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("编辑为 port 应被拒绝，实际 %v", err)
	}
	base.Kind = "host"
	base.Value = "internal-host-updated"
	base.UpdatedAt = now.Add(2 * time.Minute)
	if err := db.UpdateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("编辑为 host 应被拒绝，实际 %v", err)
	}
	base.Kind = "other"
	base.UpdatedAt = now.Add(3 * time.Minute)
	if err := db.UpdateAsset(context.Background(), base); !errors.Is(err, ErrInvalidAsset) {
		t.Fatalf("编辑为非法类型应被拒绝，实际 %v", err)
	}
}

func TestNormalizeAssetValueRejectsFalseDomainCandidates(t *testing.T) {
	validDomains := []string{
		"example.com",
		"*.example.com",
		"foo.co.uk",
		"foo.github.io",
	}
	for _, value := range validDomains {
		if _, err := NormalizeAssetValue("domain", value); err != nil {
			t.Fatalf("合法域名 %q 被拒绝: %v", value, err)
		}
	}
	invalidDomains := []string{
		"src/WebSite/bin/Kingdee.BOS.FileServer.Web.dll",
		"Kingdee.BOS.FileServer.Web.dll",
		"FileService.svc",
		"com",
		"foo.local",
		"opaque target",
		"10.0.0.1",
	}
	for _, value := range invalidDomains {
		if _, err := NormalizeAssetValue("domain", value); err == nil {
			t.Fatalf("无效域名 %q 不应通过", value)
		}
	}
	if _, err := NormalizeAssetValue("url", "src/WebSite"); err == nil {
		t.Fatal("源码路径不应作为 URL 资产")
	}
}

func TestAssetListsHideUnsupportedAndInvalidLegacyRecords(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-list-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []struct {
		id    string
		kind  string
		value string
	}{
		{id: "asset-valid", kind: "domain", value: "example.com"},
		{id: "asset-other", kind: "other", value: "src/WebSite/kdagent.aspx"},
		{id: "asset-port", kind: "port", value: "8080"},
		{
			id:    "asset-false-domain",
			kind:  "domain",
			value: "src/WebSite/bin/Kingdee.BOS.FileServer.Web.dll : Kingdee.BOS.FileServer.Web.FileService.Upload2Attachment rva=0x2D24",
		},
	} {
		if _, err := db.ExecContext(
			ctx,
			`INSERT INTO assets (
				id, project_id, owner_user_id, name, kind, value, status,
				criticality, risk_score, created_at, updated_at
			) VALUES (?, 'legacy-project', 'user-1', ?, ?, ?, 'active', 'medium', 0, ?, ?)`,
			item.id,
			item.value,
			item.kind,
			item.value,
			now.Unix(),
			now.Unix(),
		); err != nil {
			t.Fatalf("写入历史资产失败: %v", err)
		}
	}
	items, total, err := db.ListAssetsFiltered(ctx, AssetFilter{
		OwnerUserID: "user-1",
		Limit:       20,
	})
	if err != nil {
		t.Fatalf("读取资产列表失败: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "asset-valid" {
		t.Fatalf("资产列表应隐藏非法历史记录: total=%d items=%+v", total, items)
	}
}

func TestProjectAssetsExcludeLegacyPortKind(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-port-hidden.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID: "project-port-hidden", OwnerUserID: "user-1", Name: "port hidden",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-domain-visible", ProjectID: project.ID, OwnerUserID: "user-1",
		Name: "domain", Kind: "domain", Value: "example.com", Status: "active",
		Source: AssetSourceManual, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, normalized_value,
			quality_status, status, source, criticality, risk_score, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'port', '8080', '8080', 'valid', 'active', 'manual', 'medium', 0, ?, ?)`,
		"asset-port-hidden",
		project.ID,
		"user-1",
		"port",
		now.Unix(),
		now.Unix(),
	); err != nil {
		t.Fatal(err)
	}
	counts, err := db.ProjectSummary(ctx, project.ID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	assets, err := db.ListProjectAssets(ctx, project.ID, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if counts.Assets != 1 || len(assets) != 1 || assets[0].ID != "asset-domain-visible" {
		t.Fatalf("端口资产不应进入资产管理和统计: counts=%d assets=%+v", counts.Assets, assets)
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
