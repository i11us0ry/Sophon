package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestAddIntentCapsActiveIntentsPerAsset(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-intent-cap", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "意图测试", Kind: "url", Value: "https://intent.example.com",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for index := 0; index < maxActiveIntentsPerAsset; index++ {
		if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
			"title":    fmt.Sprintf("验证方向 %02d", index),
			"asset_id": "asset-intent-cap",
		}); err != nil {
			t.Fatalf("写入意图 %d 失败: %v", index, err)
		}
	}
	output, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title":    "第十一个意图",
		"asset_id": "asset-intent-cap",
	})
	if err != nil {
		t.Fatalf("达到上限不应返回错误: %v", err)
	}
	if !strings.Contains(output, "已达到上限") {
		t.Fatalf("应返回意图上限提示: %s", output)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取图谱失败: %v", err)
	}
	intentCount := 0
	for _, node := range nodes {
		if node.Kind == "intent" && node.AssetID == "asset-intent-cap" {
			intentCount++
		}
	}
	if intentCount != maxActiveIntentsPerAsset {
		t.Fatalf("活跃意图数量应保持 %d，实际 %d", maxActiveIntentsPerAsset, intentCount)
	}
}
