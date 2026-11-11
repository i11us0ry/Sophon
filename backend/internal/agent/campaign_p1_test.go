package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func seedAgentCampaign(
	t *testing.T,
	service *Service,
	ctx context.Context,
) (string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	assets := []database.Asset{
		{
			ID:          "agent-p1-asset-a",
			ProjectID:   "project-tools",
			OwnerUserID: "user-1",
			Name:        "A",
			Kind:        "url",
			Value:       "https://agent-p1.example.com/a",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "agent-p1-asset-b",
			ProjectID:   "project-tools",
			OwnerUserID: "user-1",
			Name:        "B",
			Kind:        "url",
			Value:       "https://agent-p1.example.com/b",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	parent := database.Conversation{
		ID:          "agent-p1-parent",
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Title:       "Agent P1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	items := []database.ConversationBatchItem{
		{
			Asset: assets[0],
			Conversation: database.Conversation{
				ID:          "agent-p1-child-a",
				OwnerUserID: "user-1",
				ProjectID:   "project-tools",
				Title:       "A",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		{
			Asset: assets[1],
			Conversation: database.Conversation{
				ID:          "agent-p1-child-b",
				OwnerUserID: "user-1",
				ProjectID:   "project-tools",
				Title:       "B",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
	}
	const campaignID = "agent-p1-campaign"
	if _, _, err := service.db.CreateConversationBatch(
		ctx,
		database.ConversationBatch{
			ID:                   campaignID,
			OwnerUserID:          "user-1",
			ProjectID:            "project-tools",
			ParentConversationID: parent.ID,
			Title:                "Agent P1",
			Instruction:          "验证授权资产",
			Total:                len(items),
			CreatedAt:            now,
			UpdatedAt:            now,
		},
		parent,
		items,
		"",
	); err != nil {
		t.Fatalf("创建 Campaign 失败: %v", err)
	}
	return campaignID, assets[0].ID, assets[1].ID
}

func TestRecordFactEnqueuesCredentialReuseFrontier(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	campaignID, assetA, assetB := seedAgentCampaign(t, service, ctx)

	toolCtx := execctx.WithConversationID(ctx, "agent-p1-child-a")
	if _, err := invokeProjectTool(t, service, toolCtx, "project_record_fact", map[string]interface{}{
		"asset_id":    assetA,
		"key":         "credential-admin",
		"summary":     "发现管理员凭据 admin:123456",
		"body":        "登录响应 302 且进入后台",
		"evidence":    "POST /login 响应",
		"fact_type":   "credential",
		"memory_kind": "credential",
	}); err != nil {
		t.Fatalf("写入凭据事实失败: %v", err)
	}
	items, err := service.db.ListCampaignFrontier(t.Context(), campaignID, 20)
	if err != nil {
		t.Fatalf("读取 Frontier 失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("期望 1 条凭据复用任务，实际 %+v", items)
	}
	if items[0].Kind != "credential_reuse" || items[0].AssetID != assetB {
		t.Fatalf("凭据复用目标异常: %+v", items[0])
	}
}

func TestReportFindingEnqueuesVerification(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	campaignID, assetA, _ := seedAgentCampaign(t, service, ctx)

	toolCtx := execctx.WithConversationID(ctx, "agent-p1-child-a")
	if _, err := invokeProjectTool(t, service, toolCtx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":              "SQL 注入",
		"severity":           "high",
		"target":             "https://agent-p1.example.com/a?id=1",
		"asset_id":           assetA,
		"evidence":           "sqlmap 报出数据库名",
		"evidence_refs":      []string{"conversation:agent-p1-child-a"},
		"poc":                "sqlmap -u 'https://agent-p1.example.com/a?id=1' --batch --dbs",
		"vulnerability_type": "SQL注入",
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	verifications, err := service.db.ListCampaignVerifications(t.Context(), campaignID, "", 20)
	if err != nil {
		t.Fatalf("读取验证队列失败: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("期望 1 条验证记录，实际 %+v", verifications)
	}
	if verifications[0].TaskID == "" ||
		verifications[0].Status != database.CampaignVerificationStatusPending {
		t.Fatalf("验证记录未关联任务: %+v", verifications[0])
	}
	frontier, err := service.db.ListCampaignFrontier(t.Context(), campaignID, 20)
	if err != nil {
		t.Fatalf("读取 Frontier 失败: %v", err)
	}
	if len(frontier) != 1 || frontier[0].Kind != "verify_finding" {
		t.Fatalf("未创建漏洞验证任务: %+v", frontier)
	}
}

func TestConversationBatchBriefingIncludesFrontierIntent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	campaignID, assetA, _ := seedAgentCampaign(t, service, ctx)

	if _, err := service.db.EnqueueFindingVerification(
		t.Context(),
		campaignID,
		"finding-briefing",
		assetA,
		"high",
		"SQL 注入",
	); err != nil {
		t.Fatalf("入队验证失败: %v", err)
	}
	frontier, err := service.db.ListCampaignFrontier(t.Context(), campaignID, 20)
	if err != nil || len(frontier) != 1 {
		t.Fatalf("读取 Frontier 失败: items=%+v err=%v", frontier, err)
	}
	briefCtx := execctx.WithCampaignTaskID(ctx, frontier[0].TaskID)
	briefing := service.conversationBatchBriefing(briefCtx, "agent-p1-child-a", "user-1")
	for _, want := range []string{
		"verify_finding",
		"finding-briefing",
		"project_verify_finding",
	} {
		if !strings.Contains(briefing, want) {
			t.Fatalf("任务简报缺少 %q: %s", want, briefing)
		}
	}
}
