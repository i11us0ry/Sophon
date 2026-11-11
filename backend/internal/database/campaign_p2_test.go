package database

import (
	"strings"
	"testing"
	"time"
)

func TestCampaignGroupPriorityAndFrontierROI(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)
	groups, err := db.ListCampaignGroups(ctx, campaignID)
	if err != nil || len(groups) == 0 {
		t.Fatalf("读取资产组失败: groups=%+v err=%v", groups, err)
	}
	group, err := db.SetCampaignGroupPriority(
		ctx,
		campaignID,
		groups[0].ID,
		"核心交易系统",
		95,
	)
	if err != nil {
		t.Fatalf("设置业务优先级失败: %v", err)
	}
	if group.BusinessSystem != "核心交易系统" ||
		group.BusinessPriority != 95 ||
		group.PriorityScore < 80 {
		t.Fatalf("业务优先级计算异常: %+v", group)
	}
	if _, err := db.EnqueueCampaignFrontier(ctx, CampaignFrontierItem{
		CampaignID: campaignID,
		AssetID:    assets[0],
		Kind:       "verify_finding",
		Priority:   90,
		Reason:     "ROI 测试",
		DedupeKey:  "roi-test",
		SourceType: "finding",
		SourceRef:  "finding-roi",
	}, CampaignTaskLimits{MaxAttempts: 1, MaxSegments: 6, MaxToolCalls: 60}); err != nil {
		t.Fatalf("入队失败: %v", err)
	}
	if err := db.RecomputeCampaignScheduling(ctx, campaignID); err != nil {
		t.Fatalf("重算调度失败: %v", err)
	}
	frontier, err := db.ListCampaignFrontier(ctx, campaignID, 10)
	if err != nil || len(frontier) != 1 {
		t.Fatalf("读取 Frontier 失败: items=%+v err=%v", frontier, err)
	}
	item := frontier[0]
	if item.ExpectedValue <= 0 || item.EstimatedCost <= 0 || item.ROI <= 0 {
		t.Fatalf("ROI 字段未计算: %+v", item)
	}
	if item.ExpectedValue < 90 {
		t.Fatalf("期望价值不应低于漏洞验证基线: %+v", item)
	}
}

func TestGenerateCampaignChainsFromLink(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)
	if _, err := db.CreateCampaignLink(ctx, CampaignLink{
		CampaignID: campaignID,
		ProjectID:  "campaign-p1-project",
		SrcAssetID: assets[0],
		DstAssetID: assets[1],
		Kind:       "lateral_move",
		Summary:    "入口可横向到管理端",
		Confidence: 85,
	}); err != nil {
		t.Fatalf("创建关系失败: %v", err)
	}
	created, err := db.GenerateCampaignChains(ctx, campaignID)
	if err != nil {
		t.Fatalf("生成攻击链失败: %v", err)
	}
	if created != 1 {
		t.Fatalf("期望生成 1 条攻击链，实际 %d", created)
	}
	chains, err := db.ListCampaignChains(ctx, campaignID, 10)
	if err != nil || len(chains) != 1 {
		t.Fatalf("读取攻击链失败: chains=%+v err=%v", chains, err)
	}
	if chains[0].Kind != "finding_pivot" || len(chains[0].Steps) != 2 {
		t.Fatalf("攻击链内容异常: %+v", chains[0])
	}
	frontier, err := db.ListCampaignFrontier(ctx, campaignID, 20)
	if err != nil {
		t.Fatalf("读取 Frontier 失败: %v", err)
	}
	found := false
	for _, item := range frontier {
		if item.Kind == "chain_test" && item.SourceRef == chains[0].ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("攻击链未进入 Frontier: %+v", frontier)
	}
}

func TestContinuousCampaignLifecycle(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, _ := seedCampaignP1(t, db, ctx)
	if _, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET campaign_mode = 'continuous', max_rounds = 3,
		     campaign_tool_call_budget = 500
		 WHERE id = ?`,
		campaignID,
	); err != nil {
		t.Fatalf("更新战役模式失败: %v", err)
	}
	round, err := db.AdvanceCampaignRound(ctx, campaignID)
	if err != nil || round != 1 {
		t.Fatalf("推进轮次失败: round=%d err=%v", round, err)
	}
	task, err := db.CreateCampaignReviewTask(ctx, campaignID, "user-1", round)
	if err != nil {
		t.Fatalf("创建复盘任务失败: %v", err)
	}
	if task.Kind != "campaign_review" || task.ConversationID != "p1-parent" {
		t.Fatalf("复盘任务异常: %+v", task)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks SET tool_calls = 42
		 WHERE campaign_id = ? AND id = ?`,
		campaignID,
		task.ID,
	); err != nil {
		t.Fatalf("写入工具调用失败: %v", err)
	}
	if err := db.SyncCampaignToolCalls(ctx, campaignID); err != nil {
		t.Fatalf("同步工具调用失败: %v", err)
	}
	campaign, err := db.GetCampaign(ctx, campaignID, "user-1")
	if err != nil {
		t.Fatalf("读取战役失败: %v", err)
	}
	if campaign.CampaignToolCalls != 42 {
		t.Fatalf("战役工具调用统计错误: %+v", campaign)
	}
	if err := db.StopCampaign(ctx, campaignID, "user-1"); err != nil {
		t.Fatalf("停止战役失败: %v", err)
	}
	campaign, err = db.GetCampaign(ctx, campaignID, "user-1")
	if err != nil {
		t.Fatalf("读取停止状态失败: %v", err)
	}
	if campaign.Status != CampaignStatusStopped || campaign.StoppedAt.IsZero() {
		t.Fatalf("战役停止状态异常: %+v", campaign)
	}
}

func TestCampaignMemoryDigests(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         "p2-credential-fact",
		ProjectID:  "campaign-p1-project",
		AssetID:    assets[0],
		FactType:   "credential",
		Key:        "admin-password",
		Value:      "admin:Secret123",
		Summary:    "admin:Secret123",
		Confidence: 90,
		SourceType: "conversation",
		MemoryKind: "credential",
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入凭据事实失败: %v", err)
	}
	if _, err := db.CreateCampaignLink(ctx, CampaignLink{
		CampaignID: campaignID,
		ProjectID:  "campaign-p1-project",
		SrcAssetID: assets[0],
		DstAssetID: assets[1],
		Kind:       "shared_infra",
		Summary:    "共享网关",
		Confidence: 80,
	}); err != nil {
		t.Fatalf("创建关系失败: %v", err)
	}
	if _, err := db.GenerateCampaignChains(ctx, campaignID); err != nil {
		t.Fatalf("生成攻击链失败: %v", err)
	}
	if err := db.RefreshCampaignMemory(ctx, campaignID); err != nil {
		t.Fatalf("刷新战役记忆失败: %v", err)
	}
	hot, err := db.ListCampaignMemoryDigests(ctx, campaignID, CampaignMemoryTierHot, 20)
	if err != nil || len(hot) < 3 {
		t.Fatalf("热记忆异常: items=%+v err=%v", hot, err)
	}
	for _, item := range hot {
		if item.Kind == "credentials" && item.PayloadJSON != "{}" {
			t.Fatalf("凭据记忆 payload 未脱敏: %+v", item)
		}
	}
	cold, err := db.ListCampaignMemoryDigests(ctx, campaignID, CampaignMemoryTierCold, 20)
	if err != nil || len(cold) != 1 {
		t.Fatalf("冷记忆异常: items=%+v err=%v", cold, err)
	}
	results, err := db.QueryCampaignMemory(ctx, campaignID, "战役", 20)
	if err != nil || len(results) == 0 {
		t.Fatalf("长期记忆检索失败: items=%+v err=%v", results, err)
	}
	found := false
	for _, item := range results {
		if strings.Contains(item.Summary, "战役") {
			found = true
		}
	}
	if !found {
		t.Fatalf("检索结果缺少战役摘要: %+v", results)
	}
}

func TestCampaignPausedTasksDoNotBlockCompletion(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, _ := seedCampaignP1(t, db, ctx)
	if _, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks SET status = 'paused'
		 WHERE campaign_id = ? AND kind = 'asset_scan'`,
		campaignID,
	); err != nil {
		t.Fatalf("设置暂停任务失败: %v", err)
	}
	pending, err := db.CampaignHasPendingTasks(ctx, campaignID)
	if err != nil {
		t.Fatalf("读取进行中任务失败: %v", err)
	}
	if pending {
		t.Fatalf("暂停任务不应计入进行中")
	}
	paused, err := db.CampaignHasPausedTasks(ctx, campaignID)
	if err != nil {
		t.Fatalf("读取暂停任务失败: %v", err)
	}
	if !paused {
		t.Fatalf("应能识别暂停任务")
	}
}

func TestCountToolExecutionsSince(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	seedCampaignP1(t, db, ctx)
	since := time.Now().UTC().Add(-time.Second)
	for index, conversationID := range []string{
		"p1-child-a",
		"p1-child-a",
		"p1-child-b",
	} {
		if err := db.AddProcessDetail(ctx, ProcessDetail{
			ID:             "p2-tool-event-" + string(rune('a'+index)),
			ConversationID: conversationID,
			EventType:      "tool_call",
			Message:        "nmap",
			Data:           map[string]interface{}{},
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			t.Fatalf("写入工具事件失败: %v", err)
		}
	}
	count, err := db.CountToolExecutionsSince(ctx, "p1-child-a", since)
	if err != nil || count != 2 {
		t.Fatalf("工具调用统计错误: count=%d err=%v", count, err)
	}
	future, err := db.CountToolExecutionsSince(
		ctx,
		"p1-child-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil || future != 0 {
		t.Fatalf("未来时间统计错误: count=%d err=%v", future, err)
	}
}

func TestDeleteProjectCleansCampaignP2Data(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)
	if _, err := db.CreateCampaignLink(ctx, CampaignLink{
		CampaignID: campaignID,
		ProjectID:  "campaign-p1-project",
		SrcAssetID: assets[0],
		DstAssetID: assets[1],
		Kind:       "lateral_move",
		Summary:    "清理测试",
		Confidence: 80,
	}); err != nil {
		t.Fatalf("创建关系失败: %v", err)
	}
	if _, err := db.GenerateCampaignChains(ctx, campaignID); err != nil {
		t.Fatalf("生成攻击链失败: %v", err)
	}
	if err := db.RefreshCampaignMemory(ctx, campaignID); err != nil {
		t.Fatalf("刷新记忆失败: %v", err)
	}
	if _, err := db.EnqueueFindingVerification(
		ctx,
		campaignID,
		"finding-cleanup",
		assets[0],
		"high",
		"清理测试漏洞",
	); err != nil {
		t.Fatalf("创建验证失败: %v", err)
	}
	if err := db.DeleteProject(ctx, "campaign-p1-project", "user-1"); err != nil {
		t.Fatalf("删除项目失败: %v", err)
	}
	for table, query := range map[string]string{
		"frontier":      `SELECT COUNT(*) FROM campaign_frontier WHERE campaign_id = ?`,
		"links":         `SELECT COUNT(*) FROM campaign_links WHERE campaign_id = ?`,
		"verifications": `SELECT COUNT(*) FROM campaign_verifications WHERE campaign_id = ?`,
		"chains":        `SELECT COUNT(*) FROM campaign_chains WHERE campaign_id = ?`,
		"memory":        `SELECT COUNT(*) FROM campaign_memory_digests WHERE campaign_id = ?`,
	} {
		var count int
		if err := db.QueryRowContext(ctx, query, campaignID).Scan(&count); err != nil {
			t.Fatalf("统计 %s 失败: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("删除项目后 %s 仍有 %d 条残留", table, count)
		}
	}
	var stepCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_chain_steps
		 WHERE chain_id NOT IN (SELECT id FROM campaign_chains)`,
	).Scan(&stepCount); err != nil {
		t.Fatalf("统计攻击链步骤失败: %v", err)
	}
	if stepCount != 0 {
		t.Fatalf("删除项目后仍有 %d 条攻击链步骤残留", stepCount)
	}
}
