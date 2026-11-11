package agent

import (
	"strings"
	"testing"

	"sophon/internal/database"
)

func TestFactConclusionConflictDetectsOppositeConclusions(t *testing.T) {
	existing := database.ProjectFact{
		Key:     "chain/n9e-api-unauthorized",
		Summary: "n9e clusters 未授权读取可利用，访问接口返回用户数据和监控指标",
	}
	incoming := database.ProjectFact{
		Key:     "chain/n9e-api-not-reproducible",
		Summary: "n9e clusters 未授权读取不可复现，访问接口返回 401 和鉴权错误",
	}
	if !factConclusionConflict(incoming, existing) {
		t.Fatalf("相反结论应被识别为冲突: similarity=%v", memorySimilarity(incoming.Summary, existing.Summary))
	}
	same := database.ProjectFact{
		Key:     "chain/n9e-api-confirmed",
		Summary: "n9e clusters 未授权读取可利用，返回监控指标",
	}
	if factConclusionConflict(same, existing) {
		t.Fatal("同方向结论不应被识别为冲突")
	}
}

func TestFactConclusionConflictErrorIncludesResolution(t *testing.T) {
	err := (&factConclusionConflictError{
		Key: "new-key",
		Fact: &database.ProjectFact{
			ID:         "old-id",
			Key:        "old-key",
			Summary:    "旧结论",
			Confidence: 90,
		},
	}).Error()
	for _, want := range []string{"supersedes=old-key", "evidence", "不要并存"} {
		if !strings.Contains(err, want) {
			t.Fatalf("冲突错误缺少修复指引 %q: %s", want, err)
		}
	}
}
