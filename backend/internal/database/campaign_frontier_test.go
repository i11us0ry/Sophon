package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openCampaignP1DB(t *testing.T) (*DB, context.Context) {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "campaign-p1.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, context.Background()
}

func seedCampaignP1(
	t *testing.T,
	db *DB,
	ctx context.Context,
) (string, []string) {
	t.Helper()
	now := time.Now().UTC()
	const projectID = "campaign-p1-project"
	if err := db.CreateProject(ctx, Project{
		ID:          projectID,
		OwnerUserID: "user-1",
		Name:        "P1 测试项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	assets := []Asset{
		{
			ID:          "p1-asset-a",
			ProjectID:   projectID,
			OwnerUserID: "user-1",
			Name:        "A",
			Kind:        "url",
			Value:       "https://p1.example.com/a",
			Status:      "active",
			Criticality: "high",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "p1-asset-b",
			ProjectID:   projectID,
			OwnerUserID: "user-1",
			Name:        "B",
			Kind:        "url",
			Value:       "https://p1.example.com/b",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "p1-asset-c",
			ProjectID:   projectID,
			OwnerUserID: "user-1",
			Name:        "C",
			Kind:        "url",
			Value:       "https://other.example.com/c",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
	parent := Conversation{
		ID:          "p1-parent",
		OwnerUserID: "user-1",
		ProjectID:   projectID,
		Title:       "P1 Campaign",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	items := make([]ConversationBatchItem, 0, len(assets))
	for index, asset := range assets {
		items = append(items, ConversationBatchItem{
			Asset: asset,
			Conversation: Conversation{
				ID:          "p1-child-" + string(rune('a'+index)),
				OwnerUserID: "user-1",
				ProjectID:   projectID,
				Title:       asset.Name,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		})
	}
	const campaignID = "campaign-p1"
	if _, _, err := db.CreateConversationBatch(
		ctx,
		ConversationBatch{
			ID:                   campaignID,
			OwnerUserID:          "user-1",
			ProjectID:            projectID,
			ParentConversationID: parent.ID,
			Title:                "P1 Campaign",
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
	// 隔离 P1 测试：初始资产扫描任务不参与断言。
	if _, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks SET status = ? WHERE campaign_id = ? AND kind = 'asset_scan'`,
		CampaignTaskStatusCompleted,
		campaignID,
	); err != nil {
		t.Fatalf("完成初始扫描任务失败: %v", err)
	}
	return campaignID, []string{assets[0].ID, assets[1].ID, assets[2].ID}
}

func TestCampaignP1MigrationOnLegacyTaskSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-campaign.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	if _, err := legacy.Exec(
		`CREATE TABLE campaign_tasks (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'asset_scan',
			status TEXT NOT NULL DEFAULT 'queued',
			priority INTEGER NOT NULL DEFAULT 50,
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 2,
			max_segments INTEGER NOT NULL DEFAULT 6,
			max_tool_calls INTEGER NOT NULL DEFAULT 60,
			tool_calls INTEGER NOT NULL DEFAULT 0,
			result TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL DEFAULT 0,
			finished_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
	); err != nil {
		t.Fatalf("创建旧表失败: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("旧库迁移失败: %v", err)
	}
	defer db.Close()
	var indexSQL string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master
		 WHERE type = 'index' AND name = 'idx_campaign_tasks_asset_kind'`,
	).Scan(&indexSQL); err != nil {
		t.Fatalf("读取迁移后索引失败: %v", err)
	}
	if !strings.Contains(indexSQL, "source_ref") {
		t.Fatalf("迁移后索引仍缺少任务粒度: %s", indexSQL)
	}
	for _, table := range []string{
		"campaign_frontier",
		"campaign_links",
		"campaign_verifications",
	} {
		var count int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count); err != nil || count != 1 {
			t.Fatalf("P1 表 %s 未创建: count=%d err=%v", table, count, err)
		}
	}
}

func TestCampaignFrontierDedupeAndTaskGranularity(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)

	base := CampaignFrontierItem{
		CampaignID: campaignID,
		AssetID:    assets[0],
		Kind:       "credential_reuse",
		Priority:   85,
		Reason:     "测试凭据复用",
		DedupeKey:  "credential_reuse:fact-1",
		SourceType: "fact",
		SourceRef:  "fact-1",
		IntentJSON: `{"kind":"credential_reuse"}`,
	}
	if _, err := db.EnqueueCampaignFrontier(ctx, base, CampaignTaskLimits{}); err != nil {
		t.Fatalf("首次入队失败: %v", err)
	}
	if _, err := db.EnqueueCampaignFrontier(ctx, base, CampaignTaskLimits{}); err != nil {
		t.Fatalf("重复入队失败: %v", err)
	}
	second := base
	second.DedupeKey = "credential_reuse:fact-2"
	second.SourceRef = "fact-2"
	if _, err := db.EnqueueCampaignFrontier(ctx, second, CampaignTaskLimits{}); err != nil {
		t.Fatalf("第二个事实入队失败: %v", err)
	}

	frontier, err := db.ListCampaignFrontier(ctx, campaignID, 100)
	if err != nil {
		t.Fatalf("读取 Frontier 失败: %v", err)
	}
	if len(frontier) != 2 {
		t.Fatalf("相同 dedupeKey 应去重，期望 2 条，实际 %d", len(frontier))
	}
	tasks, total, err := db.ListCampaignTasks(ctx, campaignID, "queued", 100, 0)
	if err != nil {
		t.Fatalf("读取任务失败: %v", err)
	}
	if total != 2 || len(tasks) != 2 {
		t.Fatalf("不同事实应产生独立任务，期望 2 条，实际 total=%d len=%d", total, len(tasks))
	}
	for _, task := range tasks {
		if task.Kind != "credential_reuse" {
			t.Fatalf("任务类型异常: %+v", task)
		}
	}
}

func TestEnqueueCredentialReuseTasksStaysInsideGroup(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)

	count, err := db.EnqueueCredentialReuseTasks(
		ctx,
		campaignID,
		assets[0],
		"fact-credential",
		"admin:123456",
	)
	if err != nil {
		t.Fatalf("入队凭据复用失败: %v", err)
	}
	if count != 1 {
		t.Fatalf("同组应只有 1 个复用目标，实际 %d", count)
	}
	frontier, err := db.ListCampaignFrontier(ctx, campaignID, 100)
	if err != nil {
		t.Fatalf("读取 Frontier 失败: %v", err)
	}
	if len(frontier) != 1 || frontier[0].AssetID != assets[1] {
		t.Fatalf("凭据复用不得跨授权组: %+v", frontier)
	}
}

func TestCompleteCampaignTaskUpdatesVerification(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)

	if _, err := db.EnqueueFindingVerification(
		ctx,
		campaignID,
		"finding-p1",
		assets[0],
		"high",
		"SQL 注入",
	); err != nil {
		t.Fatalf("入队漏洞验证失败: %v", err)
	}
	verification, err := db.GetCampaignVerification(ctx, campaignID, "finding-p1")
	if err != nil || verification == nil {
		t.Fatalf("读取验证记录失败: %v", err)
	}
	if verification.TaskID == "" || verification.Status != CampaignVerificationStatusPending {
		t.Fatalf("验证记录初始状态异常: %+v", verification)
	}

	claimed, err := db.ClaimCampaignTasks(ctx, campaignID, 10)
	if err != nil {
		t.Fatalf("领取任务失败: %v", err)
	}
	var taskID string
	for _, item := range claimed {
		if item.ID == verification.TaskID {
			taskID = item.ID
		}
	}
	if taskID == "" {
		t.Fatalf("未领取到验证任务: %+v", claimed)
	}
	if err := db.CompleteCampaignTask(
		ctx,
		taskID,
		CampaignTaskStatusFailed,
		"",
		"第一次验证失败",
		0,
	); err != nil {
		t.Fatalf("完成验证任务失败: %v", err)
	}
	verification, err = db.GetCampaignVerification(ctx, campaignID, "finding-p1")
	if err != nil || verification == nil {
		t.Fatalf("读取重试状态失败: %v", err)
	}
	if verification.Status != CampaignVerificationStatusPending || verification.Attempts != 1 {
		t.Fatalf("首次失败应保留重试，实际 %+v", verification)
	}

	requeued, err := db.RequeueCampaignFailedTasks(ctx, campaignID)
	if err != nil || requeued == 0 {
		t.Fatalf("重排失败任务失败: count=%d err=%v", requeued, err)
	}
	claimed, err = db.ClaimCampaignTasks(ctx, campaignID, 10)
	if err != nil {
		t.Fatalf("二次领取失败: %v", err)
	}
	taskID = ""
	for _, item := range claimed {
		if item.ID == verification.TaskID {
			taskID = item.ID
		}
	}
	if taskID == "" {
		t.Fatalf("未领取到重试任务: %+v", claimed)
	}
	if err := db.CompleteCampaignTask(
		ctx,
		taskID,
		CampaignTaskStatusCompleted,
		"已验证利用成功",
		"",
		0,
	); err != nil {
		t.Fatalf("完成重试验证失败: %v", err)
	}
	verification, err = db.GetCampaignVerification(ctx, campaignID, "finding-p1")
	if err != nil || verification == nil {
		t.Fatalf("读取最终状态失败: %v", err)
	}
	if verification.Status != CampaignVerificationStatusCompleted || verification.Attempts != 2 {
		t.Fatalf("二次成功状态异常: %+v", verification)
	}
}

func TestCampaignClaimExcludesAssetsAndSchedulesRetryBackoff(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)

	for index, assetID := range assets[:2] {
		if _, err := db.EnqueueCampaignFrontier(ctx, CampaignFrontierItem{
			CampaignID: campaignID,
			AssetID:    assetID,
			Kind:       "asset_scan",
			Priority:   80 - index,
			Reason:     "退避与资产排他测试",
			DedupeKey:  fmt.Sprintf("schedule-retry-%d", index),
			SourceType: "test",
			SourceRef:  fmt.Sprintf("source-%d", index),
			IntentJSON: `{"kind":"asset_scan"}`,
		}, CampaignTaskLimits{
			MaxAttempts:  2,
			MaxSegments:  2,
			MaxToolCalls: 10,
		}); err != nil {
			t.Fatalf("入队任务失败: %v", err)
		}
	}

	claimed, err := db.ClaimCampaignTasksExcluding(ctx, campaignID, 2, []string{assets[0]})
	if err != nil {
		t.Fatalf("排除资产领取失败: %v", err)
	}
	if len(claimed) != 1 || claimed[0].AssetID != assets[1] {
		t.Fatalf("应仅领取未占用资产任务: %+v", claimed)
	}
	task := claimed[0]

	retryScheduled, err := db.CompleteCampaignTaskWithRetry(
		ctx,
		task.ID,
		CampaignTaskStatusFailed,
		"",
		"upstream timeout",
		1,
		"timeout",
		true,
	)
	if err != nil {
		t.Fatalf("安排重试失败: %v", err)
	}
	if !retryScheduled {
		t.Fatalf("第一次 timeout 应安排重试")
	}
	stored, err := db.GetCampaignTaskByID(ctx, task.ID, "user-1")
	if err != nil || stored == nil {
		t.Fatalf("读取重试任务失败: %v", err)
	}
	if stored.Status != CampaignTaskStatusQueued ||
		stored.Attempts != 1 ||
		stored.FailureKind != "timeout" ||
		stored.NextAttemptAt.IsZero() ||
		!stored.NextAttemptAt.After(time.Now()) {
		t.Fatalf("退避状态错误: %+v", stored)
	}

	claimed, err = db.ClaimCampaignTasksExcluding(ctx, campaignID, 2, []string{assets[0]})
	if err != nil {
		t.Fatalf("退避期间领取失败: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("退避时间未到不应领取: %+v", claimed)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks SET next_attempt_at = 0 WHERE id = ?`,
		task.ID,
	); err != nil {
		t.Fatalf("提前退避时间失败: %v", err)
	}
	claimed, err = db.ClaimCampaignTasksExcluding(ctx, campaignID, 2, []string{assets[0]})
	if err != nil || len(claimed) != 1 || claimed[0].ID != task.ID {
		t.Fatalf("退避后应重新领取: items=%+v err=%v", claimed, err)
	}
	retryScheduled, err = db.CompleteCampaignTaskWithRetry(
		ctx,
		task.ID,
		CampaignTaskStatusFailed,
		"",
		"upstream timeout again",
		1,
		"timeout",
		true,
	)
	if err != nil {
		t.Fatalf("完成末次重试失败: %v", err)
	}
	if retryScheduled {
		t.Fatalf("达到最大尝试次数后不应继续重试")
	}
	stored, err = db.GetCampaignTaskByID(ctx, task.ID, "user-1")
	if err != nil || stored == nil ||
		stored.Status != CampaignTaskStatusFailed ||
		stored.Attempts != 2 {
		t.Fatalf("最终失败状态错误: item=%+v err=%v", stored, err)
	}
}

func TestPauseRunningCampaignsPreservesAutoResumeSelection(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, _ := seedCampaignP1(t, db, ctx)
	if _, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, campaign_mode = ?, resume_on_start = 1
		 WHERE id = ?`,
		CampaignStatusRunning,
		CampaignModeContinuous,
		campaignID,
	); err != nil {
		t.Fatalf("准备运行中 Campaign 失败: %v", err)
	}
	if paused, err := db.PauseRunningCampaigns(ctx); err != nil || paused != 1 {
		t.Fatalf("暂停运行中 Campaign 失败: paused=%d err=%v", paused, err)
	}
	items, err := db.ListCampaignsForAutoResume(ctx)
	if err != nil || len(items) != 1 || items[0].ID != campaignID {
		t.Fatalf("自动恢复候选错误: items=%+v err=%v", items, err)
	}
	if err := db.SetCampaignResumeOnStart(ctx, campaignID, "user-1", false); err != nil {
		t.Fatalf("关闭自动恢复失败: %v", err)
	}
	items, err = db.ListCampaignsForAutoResume(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("关闭后不应自动恢复: items=%+v err=%v", items, err)
	}
}

func TestCampaignP1CountsAndSummary(t *testing.T) {
	db, ctx := openCampaignP1DB(t)
	campaignID, assets := seedCampaignP1(t, db, ctx)

	if _, err := db.EnqueueFindingVerification(
		ctx,
		campaignID,
		"finding-count",
		assets[0],
		"critical",
		"命令注入",
	); err != nil {
		t.Fatalf("入队验证失败: %v", err)
	}
	if _, err := db.CreateCampaignLink(ctx, CampaignLink{
		CampaignID:   campaignID,
		ProjectID:    "campaign-p1-project",
		SrcAssetID:   assets[0],
		DstAssetID:   assets[1],
		Kind:         "shared_infra",
		Summary:      "共享基础设施",
		Confidence:   90,
		SrcFactID:    "fact-link",
		EvidenceRefs: []string{"fact:fact-link"},
	}); err != nil {
		t.Fatalf("创建关系失败: %v", err)
	}
	pendingFrontier, pendingVerification, linkCount, err := db.CampaignP1Counts(ctx, campaignID)
	if err != nil {
		t.Fatalf("统计 P1 数据失败: %v", err)
	}
	if pendingFrontier != 1 || pendingVerification != 1 || linkCount != 1 {
		t.Fatalf(
			"P1 统计异常: frontier=%d verification=%d links=%d",
			pendingFrontier,
			pendingVerification,
			linkCount,
		)
	}
	summary, err := db.CampaignSummary(ctx, campaignID)
	if err != nil {
		t.Fatalf("读取 Campaign 汇总失败: %v", err)
	}
	if summary.PendingFrontier != 1 ||
		summary.PendingVerification != 1 ||
		summary.LinkCount != 1 {
		t.Fatalf("Campaign 汇总缺少 P1 统计: %+v", summary)
	}
}
