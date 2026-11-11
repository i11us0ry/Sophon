package agent

import (
	"testing"
	"time"

	"sophon/internal/database"
)

func TestMemoryRankingPrioritizesPinnedAndExcludesConflicts(t *testing.T) {
	service := &Service{}
	now := time.Now().UTC()
	facts := []database.ProjectFact{
		{
			ID: "pinned", Key: "scope", Summary: "仅测试授权范围",
			MemoryKind: "scope", Pinned: true, Priority: 100,
			Importance: 90, Confidence: 100, UpdatedAt: now,
		},
		{
			ID: "relevant", Key: "sql", Summary: "目标参数存在 SQL 注入",
			MemoryKind: "finding", Priority: 70, Importance: 80,
			Confidence: 90, UpdatedAt: now,
		},
		{
			ID: "conflicted", Key: "status", Summary: "服务已关闭",
			Priority: 100, ContradictedBy: "other", UpdatedAt: now,
		},
	}
	ranked := service.rankProjectFacts(
		nil,
		"SQL 注入 服务状态",
		facts,
	)
	if len(ranked) != 2 {
		t.Fatalf("冲突事实不应参与普通召回: %+v", ranked)
	}
	if ranked[0].Fact.ID != "pinned" {
		t.Fatalf("固定记忆应优先召回: %+v", ranked)
	}
}
