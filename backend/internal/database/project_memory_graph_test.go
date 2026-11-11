package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectMemoryGraphSync(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-graph.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-memory", OwnerUserID: "user-1", Name: "记忆图谱",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-memory", ProjectID: "project-memory", OwnerUserID: "user-1",
		Name: "主站", Kind: "url", Value: "https://memory.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "finding-memory", ProjectID: "project-memory", AssetID: "asset-memory",
		OwnerUserID: "user-1", Title: "SQL 注入", Severity: "high", Status: "confirmed",
		Description: "id 参数可注入", Evidence: "sqlmap 输出",
		VerificationState: "verified", Confidence: 90, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: "goal-memory", ProjectID: "project-memory", Kind: "goal",
		Title: "确认 SQL 注入", Status: "open", Confidence: 80, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建目标失败: %v", err)
	}
	if err := db.SyncProjectMemory(ctx, "project-memory", "user-1"); err != nil {
		t.Fatalf("同步结构化记忆失败: %v", err)
	}
	assetEntity, err := db.GetProjectMemoryEntity(ctx, "project-memory", "asset", "asset-memory")
	if err != nil {
		t.Fatalf("读取资产实体失败: %v", err)
	}
	findingEntity, err := db.GetProjectMemoryEntity(ctx, "project-memory", "finding", "finding-memory")
	if err != nil {
		t.Fatalf("读取漏洞实体失败: %v", err)
	}
	relations, err := db.ListProjectMemoryRelations(ctx, "project-memory", findingEntity.ID, 20)
	if err != nil {
		t.Fatalf("读取记忆关系失败: %v", err)
	}
	found := false
	for _, relation := range relations {
		if relation.SrcEntityID == findingEntity.ID &&
			relation.Relation == "found_on" &&
			relation.DstEntityID == assetEntity.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("漏洞与资产关系缺失: %+v", relations)
	}
}

func TestProjectFactVersionsAndConflictResolution(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-conflict.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-conflict", OwnerUserID: "user-1", Name: "冲突测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	left, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-left", ProjectID: "project-conflict", FactType: "service",
		Key: "service-status-a", Summary: "服务已关闭", Value: "服务已关闭",
		MemoryKind: "asset", Priority: 80, Confidence: 80,
		SubjectType: "service", SubjectKey: "svc-1", Predicate: "status",
		ObjectType: "status", ObjectKey: "closed", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入左侧事实失败: %v", err)
	}
	right, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-right", ProjectID: "project-conflict", FactType: "service",
		Key: "service-status-b", Summary: "服务正在运行", Value: "服务正在运行",
		MemoryKind: "asset", Priority: 90, Confidence: 90,
		SubjectType: "service", SubjectKey: "svc-1", Predicate: "status",
		ObjectType: "status", ObjectKey: "open", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入右侧事实失败: %v", err)
	}
	if err := db.RecordProjectFactVersion(ctx, *left, "new-conflict"); err != nil {
		t.Fatalf("记录事实版本失败: %v", err)
	}
	if err := db.MarkProjectFactConflict(ctx, "project-conflict", left.ID, right.ID, "状态不一致"); err != nil {
		t.Fatalf("标记冲突失败: %v", err)
	}
	conflicts, err := db.ListProjectFactConflicts(ctx, "project-conflict", 20)
	if err != nil || len(conflicts) != 2 {
		t.Fatalf("冲突列表错误: %+v err=%v", conflicts, err)
	}
	versions, err := db.ListProjectFactVersions(ctx, "project-conflict", left.ID, 10)
	if err != nil || len(versions) != 1 {
		t.Fatalf("事实版本记录错误: %+v err=%v", versions, err)
	}
	if err := db.ResolveProjectFactConflict(
		ctx,
		"project-conflict",
		right.ID,
		left.ID,
		"运行状态由最新探测确认",
	); err != nil {
		t.Fatalf("解决冲突失败: %v", err)
	}
	conflicts, err = db.ListProjectFactConflicts(ctx, "project-conflict", 20)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("冲突应已解决: %+v err=%v", conflicts, err)
	}
	loser, err := db.GetProjectFactByID(ctx, "project-conflict", left.ID)
	if err != nil || loser.ValidTo.IsZero() || loser.SupersededBy != right.ID {
		t.Fatalf("失败事实未失效: %+v err=%v", loser, err)
	}
}

func TestUpdateProjectFactPreservesStructuredMemory(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-preserve.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-preserve", OwnerUserID: "user-1", Name: "字段保留",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	saved, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-preserve", ProjectID: "project-preserve", FactType: "scope",
		Key: "scope-preserve", Value: "允许测试", Summary: "允许测试",
		MemoryKind: "scope", Priority: 95, Pinned: true,
		SubjectType: "project", SubjectKey: "scope", Predicate: "allows",
		ObjectType: "value", ObjectKey: "yes", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	saved.Value = "允许测试当前接口"
	saved.Summary = "允许测试当前接口"
	saved.UpdatedAt = time.Now().UTC()
	if err := db.UpdateProjectFact(ctx, *saved); err != nil {
		t.Fatalf("更新事实失败: %v", err)
	}
	reloaded, err := db.GetProjectFactByID(ctx, "project-preserve", saved.ID)
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if reloaded.MemoryKind != "scope" || reloaded.Priority != 95 || !reloaded.Pinned ||
		reloaded.SubjectKey != "scope" || reloaded.ObjectKey != "yes" {
		t.Fatalf("更新后结构化字段被清空: %+v", reloaded)
	}
}

func TestMemorySyncDoesNotResurrectInvalidatedObjects(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-invalidation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-invalidation", OwnerUserID: "user-1", Name: "失效保护",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-invalidation", ProjectID: "project-invalidation", OwnerUserID: "user-1",
		Name: "目标", Kind: "url", Value: "https://invalidation.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "finding-invalidation", ProjectID: "project-invalidation",
		AssetID: "asset-invalidation", OwnerUserID: "user-1",
		Title: "漏洞", Severity: "high", Status: "open",
		Evidence: "evidence", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := db.SyncProjectMemory(ctx, "project-invalidation", "user-1"); err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	entity, err := db.GetProjectMemoryEntity(ctx, "project-invalidation", "asset", "asset-invalidation")
	if err != nil {
		t.Fatalf("读取实体失败: %v", err)
	}
	entity.ValidTo = now
	entity.SupersededBy = "replacement"
	entity.UpdatedAt = now
	if _, err := db.UpsertProjectMemoryEntity(ctx, *entity); err != nil {
		t.Fatalf("失效实体失败: %v", err)
	}
	findingEntity, err := db.GetProjectMemoryEntity(ctx, "project-invalidation", "finding", "finding-invalidation")
	if err != nil {
		t.Fatalf("读取 finding 实体失败: %v", err)
	}
	relation, err := db.GetProjectMemoryRelation(
		ctx,
		"project-invalidation",
		findingEntity.ID,
		"found_on",
		entity.ID,
	)
	if err != nil {
		t.Fatalf("读取关系失败: %v", err)
	}
	relation.ValidTo = now
	relation.UpdatedAt = now
	if _, err := db.UpsertProjectMemoryRelation(ctx, *relation); err != nil {
		t.Fatalf("失效关系失败: %v", err)
	}
	if err := db.SyncProjectMemory(ctx, "project-invalidation", "user-1"); err != nil {
		t.Fatalf("再次同步失败: %v", err)
	}
	reloadedEntity, err := db.GetProjectMemoryEntity(
		ctx,
		"project-invalidation",
		"asset",
		"asset-invalidation",
	)
	if err != nil || reloadedEntity.ValidTo.IsZero() || reloadedEntity.SupersededBy != "replacement" {
		t.Fatalf("同步复活了失效实体: %+v err=%v", reloadedEntity, err)
	}
	reloadedRelation, err := db.GetProjectMemoryRelation(
		ctx,
		"project-invalidation",
		findingEntity.ID,
		"found_on",
		entity.ID,
	)
	if err != nil || reloadedRelation.ValidTo.IsZero() {
		t.Fatalf("同步复活了失效关系: %+v err=%v", reloadedRelation, err)
	}
}

func TestResolveProjectFactConflictRejectsUnrelatedFacts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-conflict-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-conflict-validation", OwnerUserID: "user-1", Name: "冲突校验",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	left, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "unrelated-left", ProjectID: "project-conflict-validation",
		FactType: "general", Key: "left", Summary: "左侧", Value: "左侧",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入左侧事实失败: %v", err)
	}
	right, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "unrelated-right", ProjectID: "project-conflict-validation",
		FactType: "general", Key: "right", Summary: "右侧", Value: "右侧",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入右侧事实失败: %v", err)
	}
	if err := db.ResolveProjectFactConflict(
		ctx,
		"project-conflict-validation",
		left.ID,
		right.ID,
		"错误解决",
	); err == nil {
		t.Fatalf("非冲突事实不应允许解决")
	}
}
