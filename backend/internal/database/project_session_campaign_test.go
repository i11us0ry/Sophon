package database

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProjectSessionCampaignLifecycle(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-session-campaign.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "project-session",
		OwnerUserID: "user-1",
		Name:        "项目会话",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	assets := []Asset{
		{
			ID:          "asset-http",
			ProjectID:   project.ID,
			OwnerUserID: "user-1",
			Name:        "HTTP",
			Kind:        "url",
			Value:       "http://fengwogy.cn",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "asset-domain",
			ProjectID:   project.ID,
			OwnerUserID: "user-1",
			Name:        "域名",
			Kind:        "domain",
			Value:       "fengwogy.cn",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "asset-https",
			ProjectID:   project.ID,
			OwnerUserID: "user-1",
			Name:        "HTTPS",
			Kind:        "url",
			Value:       "https://fengwogy.cn",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	for _, asset := range assets {
		if err := db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if err := db.CreateAsset(ctx, Asset{
		ID:          "asset-inactive",
		ProjectID:   project.ID,
		OwnerUserID: "user-1",
		Name:        "停用资产",
		Kind:        "domain",
		Value:       "inactive.example.com",
		Status:      "inactive",
		Criticality: "low",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建停用资产失败: %v", err)
	}

	batch := ConversationBatch{
		ID:          "campaign-session",
		OwnerUserID: "user-1",
		ProjectID:   project.ID,
		Title:       "项目渗透测试",
		Instruction: "执行授权范围内的渗透测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	conversation := Conversation{
		ID:          "conversation-session",
		OwnerUserID: "user-1",
		ProjectID:   project.ID,
		Title:       "项目渗透测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProjectSessionCampaign(
		ctx,
		batch,
		conversation,
		batch.Instruction,
	); err != nil {
		t.Fatalf("创建项目会话战役失败: %v", err)
	}

	campaign, err := db.GetCampaign(ctx, batch.ID, "user-1")
	if err != nil {
		t.Fatalf("读取战役失败: %v", err)
	}
	if campaign.Status != CampaignStatusDraft ||
		campaign.ParentConversationID != conversation.ID ||
		campaign.Total != 1 ||
		campaign.MaxConcurrency != 1 {
		t.Fatalf("战役字段异常: %+v", campaign)
	}

	storedConversation, err := db.GetConversation(ctx, conversation.ID, "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	if storedConversation.Kind != "batch_child" ||
		storedConversation.ParentConversationID != "" ||
		storedConversation.BatchID != batch.ID {
		t.Fatalf("会话字段异常: %+v", storedConversation)
	}

	messages, err := db.GetMessages(ctx, conversation.ID, 10)
	if err != nil {
		t.Fatalf("读取消息失败: %v", err)
	}
	if len(messages) != 1 || messages[0].Role != "user" ||
		messages[0].Content != batch.Instruction {
		t.Fatalf("初始任务要求异常: %+v", messages)
	}

	task, err := db.GetCampaignTaskByConversation(ctx, conversation.ID, "user-1")
	if err != nil {
		t.Fatalf("读取后台任务失败: %v", err)
	}
	if task.Kind != "project_scan" ||
		task.Status != CampaignTaskStatusQueued ||
		task.AssetID != "" ||
		task.ConversationID != conversation.ID {
		t.Fatalf("后台任务字段异常: %+v", task)
	}
	campaignAssets, err := db.ListCampaignAssets(ctx, batch.ID, "user-1")
	if err != nil {
		t.Fatalf("读取 Campaign 授权资产失败: %v", err)
	}
	if len(campaignAssets) != len(assets) {
		t.Fatalf("Campaign 授权资产数量应为 %d，实际 %d", len(assets), len(campaignAssets))
	}
	for _, asset := range assets {
		contained, err := db.CampaignContainsAsset(ctx, batch.ID, asset.ID)
		if err != nil || !contained {
			t.Fatalf("Campaign 应包含资产 %s: contained=%v err=%v", asset.ID, contained, err)
		}
	}

	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM campaign_endpoints WHERE campaign_id = ?`,
		batch.ID,
	); err != nil {
		t.Fatalf("清理授权映射失败: %v", err)
	}
	if err := db.backfillProjectSessionCampaignEndpoints(ctx); err != nil {
		t.Fatalf("回填 Campaign 授权资产失败: %v", err)
	}
	campaignAssets, err = db.ListCampaignAssets(ctx, batch.ID, "user-1")
	if err != nil || len(campaignAssets) != len(assets) {
		t.Fatalf("回填后 Campaign 授权资产异常: count=%d err=%v", len(campaignAssets), err)
	}
	queued, err := db.QueuedCampaignConversationIDs(
		ctx,
		"user-1",
		[]string{conversation.ID},
	)
	if err != nil || !queued[conversation.ID] {
		t.Fatalf("排队状态查询异常: queued=%v err=%v", queued, err)
	}
	if err := db.recoverDraftProjectSessionCampaigns(ctx); err != nil {
		t.Fatalf("恢复 draft Campaign 失败: %v", err)
	}
	campaign, err = db.GetCampaign(ctx, batch.ID, "user-1")
	if err != nil {
		t.Fatalf("读取恢复后的 Campaign 失败: %v", err)
	}
	if campaign.Status != CampaignStatusPaused || !campaign.ResumeOnStart {
		t.Fatalf("draft Campaign 应转为可恢复 paused: %+v", campaign)
	}
	resumeItems, err := db.ListCampaignsForAutoResume(ctx)
	if err != nil {
		t.Fatalf("读取自动恢复列表失败: %v", err)
	}
	foundResume := false
	for _, item := range resumeItems {
		if item.ID == batch.ID {
			foundResume = true
			break
		}
	}
	if !foundResume {
		t.Fatalf("恢复后的 Campaign 应进入自动恢复列表")
	}
	hasUnfinished, err := db.ProjectHasUnfinishedCampaign(ctx, project.ID, "user-1")
	if err != nil || !hasUnfinished {
		t.Fatalf("未结束战役检查异常: value=%v err=%v", hasUnfinished, err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches SET status = ?, stopped_at = 0 WHERE id = ?`,
		CampaignStatusCompleted,
		batch.ID,
	); err != nil {
		t.Fatalf("标记 Campaign 完成失败: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM campaign_endpoints WHERE campaign_id = ?`,
		batch.ID,
	); err != nil {
		t.Fatalf("清理已完成 Campaign 映射失败: %v", err)
	}
	if err := db.backfillProjectSessionCampaignEndpoints(ctx); err != nil {
		t.Fatalf("已完成 Campaign 不应触发回填错误: %v", err)
	}
	campaignAssets, err = db.ListCampaignAssets(ctx, batch.ID, "user-1")
	if err != nil {
		t.Fatalf("读取已完成 Campaign 资产失败: %v", err)
	}
	if len(campaignAssets) != 0 {
		t.Fatalf("已完成 Campaign 不应被历史回填修改: %d", len(campaignAssets))
	}

	if _, err := db.DeleteConversations(
		ctx,
		[]string{conversation.ID},
		"user-1",
	); err != nil {
		t.Fatalf("删除会话失败: %v", err)
	}
	if _, err := db.GetCampaign(ctx, batch.ID, "user-1"); err == nil {
		t.Fatalf("删除会话后内部战役应一并清理")
	}
}

func TestCreateProjectSessionCampaignRejectsConcurrentDuplicate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-session-race.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-race",
		OwnerUserID: "user-1",
		Name:        "并发项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID:          "asset-race",
		ProjectID:   "project-race",
		OwnerUserID: "user-1",
		Name:        "并发资产",
		Kind:        "domain",
		Value:       "race.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- db.CreateProjectSessionCampaign(
				ctx,
				ConversationBatch{
					ID:          fmt.Sprintf("campaign-race-%d", index),
					OwnerUserID: "user-1",
					ProjectID:   "project-race",
					Title:       "并发测试",
					CreatedAt:   now,
					UpdatedAt:   now,
				},
				Conversation{
					ID:          fmt.Sprintf("conversation-race-%d", index),
					OwnerUserID: "user-1",
					ProjectID:   "project-race",
					Title:       "并发测试",
					CreatedAt:   now,
					UpdatedAt:   now,
				},
				"执行并发测试",
			)
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	successes := 0
	conflicts := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrProjectCampaignActive):
			conflicts++
		default:
			t.Fatalf("并发创建返回异常错误: %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("并发创建应一成一拒，success=%d conflict=%d", successes, conflicts)
	}
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM conversation_batches WHERE project_id = 'project-race'`,
	).Scan(&count); err != nil {
		t.Fatalf("读取并发 Campaign 数量失败: %v", err)
	}
	if count != 1 {
		t.Fatalf("同一项目只能存在一个未结束 Campaign，实际 %d", count)
	}
}

func TestCreateProjectSessionCampaignRequiresActiveAsset(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-session-no-active-assets.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-no-active",
		OwnerUserID: "user-1",
		Name:        "无启用资产",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID:          "asset-retired",
		ProjectID:   "project-no-active",
		OwnerUserID: "user-1",
		Name:        "退役资产",
		Kind:        "domain",
		Value:       "retired.example.com",
		Status:      "retired",
		Criticality: "low",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建退役资产失败: %v", err)
	}

	err = db.CreateProjectSessionCampaign(
		ctx,
		ConversationBatch{
			ID:          "campaign-no-active",
			OwnerUserID: "user-1",
			ProjectID:   "project-no-active",
			Title:       "无启用资产",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		Conversation{
			ID:          "conversation-no-active",
			OwnerUserID: "user-1",
			ProjectID:   "project-no-active",
			Title:       "无启用资产",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		"执行测试",
	)
	if !errors.Is(err, ErrNoActiveProjectAssets) {
		t.Fatalf("无启用资产时应拒绝创建 Campaign: %v", err)
	}
}
