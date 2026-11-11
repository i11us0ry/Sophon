package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestProjectFactToolsUseConversationAssetScope(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	for _, assetID := range []string{"asset-a", "asset-b"} {
		if err := service.db.CreateAsset(ctx, database.Asset{
			ID:          assetID,
			ProjectID:   "project-tools",
			OwnerUserID: "user-1",
			Name:        assetID,
			Kind:        "url",
			Value:       "https://" + assetID + ".example.com",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}); err != nil {
			t.Fatalf("创建资产 %s 失败: %v", assetID, err)
		}
	}

	ctxA := execctx.WithAssetID(ctx, "asset-a")
	ctxB := execctx.WithAssetID(ctx, "asset-b")
	if _, err := invokeProjectTool(t, service, ctxA, "project_record_fact", map[string]interface{}{
		"key": "service.fingerprint", "summary": "A 站 nginx 1.18",
	}); err != nil {
		t.Fatalf("写入资产 A 事实失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctxB, "project_record_fact", map[string]interface{}{
		"key": "service.fingerprint", "summary": "B 站 nginx 1.24",
	}); err != nil {
		t.Fatalf("写入资产 B 事实失败: %v", err)
	}

	outA, err := invokeProjectTool(t, service, ctxA, "project_list_facts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("读取资产 A 事实失败: %v", err)
	}
	if !strings.Contains(outA, "A 站 nginx 1.18") || strings.Contains(outA, "B 站 nginx 1.24") {
		t.Fatalf("资产 A 的事实范围错误: %q", outA)
	}
	outB, err := invokeProjectTool(t, service, ctxB, "project_list_facts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("读取资产 B 事实失败: %v", err)
	}
	if !strings.Contains(outB, "B 站 nginx 1.24") || strings.Contains(outB, "A 站 nginx 1.18") {
		t.Fatalf("资产 B 的事实范围错误: %q", outB)
	}
}
