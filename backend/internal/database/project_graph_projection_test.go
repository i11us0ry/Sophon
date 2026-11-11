package database

import (
	"fmt"
	"testing"
	"time"
)

func TestProjectFactsForGraphLimitsLowValueFactsPerAsset(t *testing.T) {
	now := time.Now().UTC()
	facts := make([]ProjectFact, 0, 20)
	for index := 0; index < 20; index++ {
		facts = append(facts, ProjectFact{
			ID:         fmt.Sprintf("fact-%02d", index),
			AssetID:    "asset-projection",
			Key:        fmt.Sprintf("note/low-%02d", index),
			Priority:   50,
			Confidence: 80,
			UpdatedAt:  now.Add(time.Duration(index) * time.Second),
		})
	}
	kept := projectFactsForGraph(facts)
	if len(kept) > maxMaterializedFactsPerAsset {
		t.Fatalf("每个资产最多物化 %d 条普通事实，实际 %d", maxMaterializedFactsPerAsset, len(kept))
	}

	highValue := append([]ProjectFact{}, facts...)
	highValue[0].Priority = 95
	kept = projectFactsForGraph(highValue)
	found := false
	for _, fact := range kept {
		if fact.ID == "fact-00" {
			found = true
		}
	}
	if !found {
		t.Fatalf("高优先级事实必须物化")
	}
}

func TestProjectFactsForGraphLimitsProjectTotal(t *testing.T) {
	now := time.Now().UTC()
	facts := make([]ProjectFact, 0, 500)
	for index := 0; index < 500; index++ {
		facts = append(facts, ProjectFact{
			ID:         fmt.Sprintf("many-%03d", index),
			AssetID:    fmt.Sprintf("asset-%03d", index),
			Key:        fmt.Sprintf("note/fact-%03d", index),
			Priority:   50,
			Confidence: 80,
			UpdatedAt:  now,
		})
	}
	kept := projectFactsForGraph(facts)
	if len(kept) > maxMaterializedFactsPerProject {
		t.Fatalf("项目级事实物化应限制在 %d，实际 %d", maxMaterializedFactsPerProject, len(kept))
	}
}
