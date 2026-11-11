package database

import (
	"context"
	"testing"
	"time"
)

func TestListProjectCampaignChains(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	created, err := db.CreateCampaignChain(ctx, CampaignChain{
		ID:            "chain-project-1",
		CampaignID:    "campaign-1",
		ProjectID:     "project-chain-list",
		Fingerprint:   "chain-project-1",
		Title:         "跨资产凭据复用",
		Kind:          "credential_reuse",
		Status:        CampaignChainStatusVerified,
		Priority:      88,
		Confidence:    86,
		EntryAssetID:  "asset-a",
		TargetAssetID: "asset-b",
		CreatedAt:     now,
		UpdatedAt:     now,
		Steps: []CampaignChainStep{
			{Kind: "entry", AssetID: "asset-a", Summary: "获取凭据"},
			{Kind: "pivot", AssetID: "asset-b", Summary: "复用到目标资产"},
		},
	})
	if err != nil {
		t.Fatalf("创建攻击链失败: %v", err)
	}
	if _, err := db.CreateCampaignChain(ctx, CampaignChain{
		ID:          "chain-project-2",
		CampaignID:  "campaign-2",
		ProjectID:   "project-chain-other",
		Fingerprint: "chain-project-2",
		Title:       "其他项目攻击链",
		Kind:        "finding_pivot",
		Status:      CampaignChainStatusCandidate,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建其他项目攻击链失败: %v", err)
	}
	items, err := db.ListProjectCampaignChains(ctx, "project-chain-list", 10)
	if err != nil {
		t.Fatalf("读取项目攻击链失败: %v", err)
	}
	if len(items) != 1 || items[0].ID != created.ID || len(items[0].Steps) != 2 {
		t.Fatalf("项目攻击链内容异常: %+v", items)
	}
}
