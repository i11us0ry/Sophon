package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestCampaignP2RecordLinkGeneratesChainAndMemory(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	campaignID, assetA, assetB := seedAgentCampaign(t, service, ctx)
	toolCtx := execctx.WithConversationID(ctx, "agent-p1-child-a")

	if _, err := invokeProjectTool(t, service, toolCtx, "project_record_link", map[string]interface{}{
		"src_asset_id": assetA,
		"dst_asset_id": assetB,
		"kind":         "lateral_move",
		"summary":      "入口可横向到管理端",
		"confidence":   85,
	}); err != nil {
		t.Fatalf("记录跨资产关系失败: %v", err)
	}
	chains, err := service.db.ListCampaignChains(t.Context(), campaignID, 10)
	if err != nil || len(chains) != 1 {
		t.Fatalf("攻击链未生成: chains=%+v err=%v", chains, err)
	}
	output, err := invokeProjectTool(t, service, toolCtx, "project_list_chains", map[string]interface{}{})
	if err != nil {
		t.Fatalf("读取攻击链工具失败: %v", err)
	}
	if !strings.Contains(output, "横向") && !strings.Contains(output, "攻击链") {
		t.Fatalf("攻击链工具输出异常: %s", output)
	}
	memoryOutput, err := invokeProjectTool(t, service, toolCtx, "project_query_memory", map[string]interface{}{
		"keyword": "战役",
	})
	if err != nil {
		t.Fatalf("查询长期记忆失败: %v", err)
	}
	if !strings.Contains(memoryOutput, "战役") {
		t.Fatalf("长期记忆输出异常: %s", memoryOutput)
	}
	situation := service.projectSituationForContext(
		execctx.WithCampaignID(toolCtx, campaignID),
		"project-tools",
		"user-1",
		"agent-p1-child-a",
	)
	if !strings.Contains(situation, "战役长期记忆") {
		t.Fatalf("热记忆未注入态势包: %s", situation)
	}
}

func TestCampaignP2SetGroupPriority(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	campaignID, _, _ := seedAgentCampaign(t, service, ctx)
	groups, err := service.db.ListCampaignGroups(t.Context(), campaignID)
	if err != nil || len(groups) == 0 {
		t.Fatalf("读取资产组失败: groups=%+v err=%v", groups, err)
	}
	toolCtx := execctx.WithConversationID(ctx, "agent-p1-child-a")
	output, err := invokeProjectTool(t, service, toolCtx, "project_set_group_priority", map[string]interface{}{
		"group_id":          groups[0].ID,
		"business_system":   "核心交易系统",
		"business_priority": 95,
	})
	if err != nil {
		t.Fatalf("设置业务优先级失败: %v", err)
	}
	if !strings.Contains(output, "核心交易系统") {
		t.Fatalf("业务优先级输出异常: %s", output)
	}
	groups, err = service.db.ListCampaignGroups(t.Context(), campaignID)
	if err != nil {
		t.Fatalf("重新读取资产组失败: %v", err)
	}
	if groups[0].BusinessSystem != "核心交易系统" || groups[0].PriorityScore < 80 {
		t.Fatalf("业务优先级未落库: %+v", groups[0])
	}
}

func TestCampaignP2RejectsOutOfScopeLink(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	_, assetA, _ := seedAgentCampaign(t, service, ctx)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "agent-p2-outside-asset",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "范围外资产",
		Kind:        "url",
		Value:       "https://outside.example.com/",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建范围外资产失败: %v", err)
	}
	toolCtx := execctx.WithConversationID(ctx, "agent-p1-child-a")
	_, err := invokeProjectTool(t, service, toolCtx, "project_record_link", map[string]interface{}{
		"src_asset_id": assetA,
		"dst_asset_id": "agent-p2-outside-asset",
		"kind":         "lateral_move",
		"summary":      "越界测试",
		"confidence":   80,
	})
	if err == nil || !strings.Contains(err.Error(), "授权范围") {
		t.Fatalf("范围外资产应被拒绝，实际: %v", err)
	}
	_, err = invokeProjectTool(t, service, toolCtx, "project_add_intent", map[string]interface{}{
		"title":    "越界 intent",
		"asset_id": "agent-p2-outside-asset",
	})
	if err == nil || !strings.Contains(err.Error(), "授权范围") {
		t.Fatalf("范围外资产不应被写入 intent，实际: %v", err)
	}
}
