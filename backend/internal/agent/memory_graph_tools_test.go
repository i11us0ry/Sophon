package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProjectMemoryGraphTools(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	first, err := invokeProjectTool(t, service, ctx, "project_upsert_entity", map[string]interface{}{
		"entity_type": "asset",
		"entity_key":  "asset-memory-tool",
		"label":       "测试资产",
		"summary":     "https://memory-tool.example",
		"confidence":  90,
		"priority":    80,
	})
	if err != nil || !strings.Contains(first, "asset-memory-tool") {
		t.Fatalf("写入资产实体失败: %q err=%v", first, err)
	}
	assetEntity, err := service.db.GetProjectMemoryEntity(ctx, "project-tools", "asset", "asset-memory-tool")
	if err != nil {
		t.Fatalf("读取资产实体失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_upsert_entity", map[string]interface{}{
		"entity_type": "endpoint",
		"entity_key":  "endpoint-memory-tool",
		"label":       "注入接口",
		"summary":     "/vul/sqli.php",
	}); err != nil {
		t.Fatalf("写入接口实体失败: %v", err)
	}
	endpointEntity, err := service.db.GetProjectMemoryEntity(ctx, "project-tools", "endpoint", "endpoint-memory-tool")
	if err != nil {
		t.Fatalf("读取接口实体失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_link_entities", map[string]interface{}{
		"src_entity_id": assetEntity.ID,
		"relation":      "exposes",
		"dst_entity_id": endpointEntity.ID,
		"confidence":    90,
	})
	if err != nil || !strings.Contains(out, "exposes") {
		t.Fatalf("写入实体关系失败: %q err=%v", out, err)
	}
	graph, err := invokeProjectTool(t, service, ctx, "project_memory_graph", map[string]interface{}{
		"entity_id": assetEntity.ID,
	})
	if err != nil || !strings.Contains(graph, endpointEntity.ID) {
		t.Fatalf("读取记忆图谱失败: %q err=%v", graph, err)
	}
}

func TestStructuredFactConflictBlocksAndResolves(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":          "service-status-a",
		"summary":      "服务已关闭",
		"fact_type":    "service",
		"memory_kind":  "asset",
		"priority":     85,
		"confidence":   80,
		"subject_type": "service",
		"subject_key":  "svc-1",
		"predicate":    "status",
		"object_type":  "status",
		"object_key":   "closed",
	}); err != nil {
		t.Fatalf("写入事实 A 失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":          "service-status-b",
		"summary":      "服务正在运行",
		"fact_type":    "service",
		"memory_kind":  "asset",
		"priority":     90,
		"confidence":   90,
		"subject_type": "service",
		"subject_key":  "svc-1",
		"predicate":    "status",
		"object_type":  "status",
		"object_key":   "open",
	}); err != nil {
		t.Fatalf("写入事实 B 失败: %v", err)
	}
	conflicts, err := invokeProjectTool(t, service, ctx, "project_fact_audit", map[string]interface{}{"action": "list"})
	if err != nil || !strings.Contains(conflicts, "service-status-a") || !strings.Contains(conflicts, "service-status-b") {
		t.Fatalf("事实冲突未建立: %q err=%v", conflicts, err)
	}
	situation := service.projectSituation(ctx, "project-tools", "user-1")
	if !strings.Contains(situation, "未解决事实冲突") {
		t.Fatalf("任务态势应包含冲突警告:\n%s", situation)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 2 {
		t.Fatalf("读取冲突事实失败: %+v err=%v", facts, err)
	}
	winnerID := ""
	loserID := ""
	for _, fact := range facts {
		if fact.Key == "service-status-b" {
			winnerID = fact.ID
		}
		if fact.Key == "service-status-a" {
			loserID = fact.ID
		}
	}
	out, err := invokeProjectTool(t, service, ctx, "project_fact_audit", map[string]interface{}{
		"action":    "resolve",
		"winner_id": winnerID,
		"loser_id":  loserID,
		"reason":    "最新探测确认服务正在运行",
	})
	if err != nil || !strings.Contains(out, "已解决") {
		t.Fatalf("解决冲突失败: %q err=%v", out, err)
	}
	conflicts, err = invokeProjectTool(t, service, ctx, "project_fact_audit", map[string]interface{}{"action": "list"})
	if err != nil || !strings.Contains(conflicts, "没有未解决") {
		t.Fatalf("冲突应已清空: %q err=%v", conflicts, err)
	}
	loser, err := service.db.GetProjectFactByID(ctx, "project-tools", loserID)
	if err != nil || loser.ValidTo.IsZero() || loser.SupersededBy != winnerID {
		t.Fatalf("失败事实未失效: %+v err=%v", loser, err)
	}
}

func TestFinalizationBlocksHighPriorityConflict(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	left, err := service.db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: "conflict-left", ProjectID: "project-tools", FactType: "scope",
		Key: "scope-a", Summary: "允许测试", Value: "允许测试",
		MemoryKind: "scope", Priority: 95, Confidence: 90,
		SubjectType: "project", SubjectKey: "scope", Predicate: "allows",
		ObjectType: "value", ObjectKey: "yes", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	right, err := service.db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: "conflict-right", ProjectID: "project-tools", FactType: "scope",
		Key: "scope-b", Summary: "禁止测试", Value: "禁止测试",
		MemoryKind: "scope", Priority: 95, Confidence: 90,
		SubjectType: "project", SubjectKey: "scope", Predicate: "allows",
		ObjectType: "value", ObjectKey: "no", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	if err := service.db.MarkProjectFactConflict(ctx, "project-tools", left.ID, right.ID, "范围冲突"); err != nil {
		t.Fatalf("标记冲突失败: %v", err)
	}
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		&runCapture{},
	)
	if decision.Allowed || !strings.Contains(strings.Join(decision.Reasons, "\n"), "事实冲突") {
		t.Fatalf("高优先级冲突应阻止最终化: %+v", decision)
	}
}
