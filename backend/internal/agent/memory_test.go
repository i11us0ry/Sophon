package agent

import (
	"context"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestMemorySimilarity(t *testing.T) {
	if score := memorySimilarity("目标 IP 是 10.0.0.1", "目标 IP 是 10.0.0.1"); score < 0.99 {
		t.Fatalf("相同文本相似度应为 1，实际 %.2f", score)
	}
	if score := memorySimilarity("目标 IP 是 10.0.0.1", "数据库版本是 MySQL 8.0"); score > 0.3 {
		t.Fatalf("无关文本相似度应较低，实际 %.2f", score)
	}
}

func openMemoryTestEnv(t *testing.T) (*Service, *database.DB) {
	t.Helper()
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-mem",
		OwnerUserID: "user-1",
		Name:        "记忆测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	return &Service{db: db, cfg: config.Config{}}, db
}

func TestConsolidateFactDecisions(t *testing.T) {
	service, db := openMemoryTestEnv(t)
	ctx := context.Background()
	base := database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "service",
		Key:        "目标IP",
		Summary:    "目标 IP 是 10.0.0.1",
		Confidence: 80,
		SourceType: "conversation",
	}

	added, err := service.consolidateFact(ctx, "project-mem", base)
	if err != nil {
		t.Fatalf("新增记忆失败: %v", err)
	}
	if added.Action != "ADD" || added.Fact == nil || added.Fact.Version != 1 {
		t.Fatalf("首次写入应为 ADD(v1): %+v", added)
	}

	none, err := service.consolidateFact(ctx, "project-mem", base)
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if none.Action != "NONE" {
		t.Fatalf("同 key 同内容应为 NONE，实际 %s", none.Action)
	}

	changed := base
	changed.Summary = "目标 IP 是 10.0.0.2（已变更）"
	updated, err := service.consolidateFact(ctx, "project-mem", changed)
	if err != nil {
		t.Fatalf("更新记忆失败: %v", err)
	}
	if updated.Action != "UPDATE" || updated.Fact.Version != 2 {
		t.Fatalf("同 key 变化应为 UPDATE(v2): %+v", updated)
	}

	merged, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "service",
		Key:        "目标IP地址",
		Summary:    "目标 IP 是 10.0.0.2（已变更）",
		Confidence: 85,
		SourceType: "conversation",
	})
	if err != nil {
		t.Fatalf("语义合并失败: %v", err)
	}
	if merged.Action != "UPDATE" || merged.Reason != "semantic-merge" {
		t.Fatalf("高相似异 key 应合并: %+v", merged)
	}
	if merged.Fact.Key != "目标IP" {
		t.Fatalf("合并应保留已有 key，实际 %s", merged.Fact.Key)
	}

	var factCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_facts WHERE project_id = 'project-mem' AND valid_to = 0`,
	).Scan(&factCount); err != nil {
		t.Fatalf("统计记忆失败: %v", err)
	}
	if factCount != 1 {
		t.Fatalf("语义合并后应只有 1 条有效记忆，实际 %d", factCount)
	}

	writes, err := db.ListMemoryWrites(ctx, "project-mem", 20)
	if err != nil {
		t.Fatalf("读取记忆审计失败: %v", err)
	}
	if len(writes) != 4 {
		t.Fatalf("应记录 4 次写决策（ADD/NONE/UPDATE/语义合并），实际 %d", len(writes))
	}
}

func TestSupersedeFactMarksInvalid(t *testing.T) {
	service, db := openMemoryTestEnv(t)
	ctx := context.Background()

	old, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "finding",
		Key:        "旧结论",
		Summary:    "旧结论：22 端口关闭",
		Confidence: 60,
	})
	if err != nil {
		t.Fatalf("写入旧结论失败: %v", err)
	}
	replacement, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "finding",
		Key:        "新结论",
		Summary:    "新结论：22 端口开放（已复测）",
		Confidence: 95,
	})
	if err != nil {
		t.Fatalf("写入新结论失败: %v", err)
	}
	if err := service.supersedeFact(ctx, "project-mem", "", "旧结论", replacement.Fact); err != nil {
		t.Fatalf("标记失效失败: %v", err)
	}

	facts, err := db.ListProjectFacts(ctx, "project-mem")
	if err != nil {
		t.Fatalf("读取有效记忆失败: %v", err)
	}
	for _, fact := range facts {
		if fact.ID == old.Fact.ID {
			t.Fatalf("失效记忆不应出现在有效列表: %+v", fact)
		}
	}
	stored, err := db.GetProjectFactByKey(ctx, "project-mem", "", "旧结论")
	if err != nil || stored == nil {
		t.Fatalf("读取旧记忆失败: %v", err)
	}
	if stored.ValidTo.IsZero() || stored.SupersededBy != replacement.Fact.ID {
		t.Fatalf("旧记忆应标记 valid_to 与 superseded_by: %+v", stored)
	}
}

// TestConsolidateFactRejectsLowConfidenceOverwrite 覆盖审计修复：
// 低置信且无新证据的覆盖/失效请求必须被拒绝。
func TestConsolidateFactRejectsLowConfidenceOverwrite(t *testing.T) {
	service, _ := openMemoryTestEnv(t)
	ctx := context.Background()

	original, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "service",
		Key:        "目标端口",
		Summary:    "22 端口开放（nmap 确认）",
		Evidence:   "nmap -sV 输出",
		Confidence: 90,
	})
	if err != nil {
		t.Fatalf("写入原始记忆失败: %v", err)
	}

	blocked, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "service",
		Key:        "目标端口",
		Summary:    "22 端口关闭",
		Confidence: 30,
	})
	if err != nil {
		t.Fatalf("低置信覆盖不应报错，应判定为 NONE: %v", err)
	}
	if blocked.Action != "NONE" || blocked.Reason != "rejected-lower-confidence" {
		t.Fatalf("低置信覆盖应被拒绝: %+v", blocked)
	}

	replacement, err := service.consolidateFact(ctx, "project-mem", database.ProjectFact{
		ProjectID:  "project-mem",
		FactType:   "service",
		Key:        "新端口结论",
		Summary:    "22 端口关闭",
		Confidence: 30,
	})
	if err != nil {
		t.Fatalf("写入替代记忆失败: %v", err)
	}
	if err := service.supersedeFact(ctx, "project-mem", "", "目标端口", replacement.Fact); err == nil {
		t.Fatalf("低置信替代事实不应允许失效旧记忆")
	}
	if original.Fact == nil || original.Action != "ADD" {
		t.Fatalf("原始记忆应正常写入: %+v", original)
	}
}
