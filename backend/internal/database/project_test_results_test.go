package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeProjectTestResultStatusAliases(t *testing.T) {
	for input, want := range map[string]string{
		"":            "untested",
		"open":        "untested",
		"pending":     "untested",
		"todo":        "untested",
		"queued":      "untested",
		"working":     "running",
		"in_progress": "running",
		"in-progress": "running",
	} {
		got, ok := NormalizeProjectTestResultStatus(input)
		if !ok || got != want {
			t.Fatalf("状态别名 %q 应归一为 %q，实际 %q ok=%v", input, want, got, ok)
		}
	}
	if got, ok := NormalizeProjectTestResultStatus("invalid"); ok || got != "invalid" {
		t.Fatalf("非法状态必须拒绝，实际 %q ok=%v", got, ok)
	}
}

func TestProjectTestResultsUpsertAndCoverageState(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test-results.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-tests", OwnerUserID: "user-1", Name: "测试矩阵",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "running", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "tested_clean", Result: "布尔对照无差异",
		Evidence: "响应长度一致", Confidence: 90, CreatedAt: now,
	}); err != nil {
		t.Fatalf("更新测试结果失败: %v", err)
	}
	items, err := db.ListProjectTestResults(ctx, "project-tests", 20)
	if err != nil || len(items) != 1 {
		t.Fatalf("相同测试维度应按唯一键更新: %+v err=%v", items, err)
	}
	if items[0].Status != "tested_clean" || !IsProjectTestResultCovered(items[0].Status) {
		t.Fatalf("测试状态更新错误: %+v", items[0])
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "untested",
	}); err != nil {
		t.Fatalf("重复规划失败: %v", err)
	}
	items, err = db.ListProjectTestResults(ctx, "project-tests", 20)
	if err != nil || len(items) != 1 || items[0].Status != "tested_clean" {
		t.Fatalf("已完成假设不应被降级: %+v err=%v", items, err)
	}
	if IsProjectTestResultCovered("running") || IsProjectTestResultCovered("blocked") {
		t.Fatalf("running/blocked 不应算作覆盖")
	}
}

func TestClaimNextProjectHypothesisIsAtomic(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "claim-results.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-claim", OwnerUserID: "user-1", Name: "领取测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for index, candidate := range []struct {
		assetID  string
		priority int
	}{
		{assetID: "asset-1", priority: 90},
		{assetID: "asset-2", priority: 80},
		{assetID: "asset-1", priority: 70},
	} {
		if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
			ProjectID: "project-claim", AssetID: candidate.assetID,
			Dimension: "测试方向", Technique: "技术-" + string(rune('A'+index)),
			Status: "untested", Priority: candidate.priority, CreatedAt: now,
		}); err != nil {
			t.Fatalf("创建假设失败: %v", err)
		}
	}
	first, err := db.ClaimNextProjectHypothesis(ctx, "project-claim")
	if err != nil || first == nil || first.Status != "running" || first.Attempts != 1 {
		t.Fatalf("首次领取失败: item=%+v err=%v", first, err)
	}
	second, err := db.ClaimNextProjectHypothesis(ctx, "project-claim")
	if err != nil || second == nil || second.ID == first.ID || second.Status != "running" {
		t.Fatalf("第二次应领取不同假设: first=%+v second=%+v err=%v", first, second, err)
	}
	third, err := db.ClaimNextProjectHypothesis(ctx, "project-claim")
	if err != nil || third == nil || third.ID == first.ID || third.ID == second.ID {
		t.Fatalf("同一资产下的独立假设应允许并发领取: item=%+v err=%v", third, err)
	}
	fourth, err := db.ClaimNextProjectHypothesis(ctx, "project-claim")
	if err != nil || fourth != nil {
		t.Fatalf("全部假设领取后不应返回任务: item=%+v err=%v", fourth, err)
	}
}

func TestClaimNextProjectHypothesisPreservesRetryReason(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "claim-retry-reason.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-claim-retry", OwnerUserID: "user-1", Name: "恢复重试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	reason := ProjectHypothesisServiceRestartPrefix + ": 服务重启导致 Worker 中断"
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID:      "project-claim-retry",
		Dimension:      "恢复执行",
		Technique:      "restart",
		Status:         "untested",
		ExecutionState: ProjectExecutionOpen,
		StateReason:    reason,
		Priority:       90,
	}); err != nil {
		t.Fatalf("创建恢复假设失败: %v", err)
	}
	claimed, err := db.ClaimNextProjectHypothesis(ctx, "project-claim-retry")
	if err != nil || claimed == nil {
		t.Fatalf("领取恢复假设失败: %+v err=%v", claimed, err)
	}
	if claimed.StateReason != reason {
		t.Fatalf("领取后丢失重试原因: got=%q want=%q", claimed.StateReason, reason)
	}
	if claimed.Attempts != 1 {
		t.Fatalf("恢复执行次数错误: %d", claimed.Attempts)
	}
}

func TestProjectIntentPauseResumeAndStopStates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-intent-states.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-intent-states", OwnerUserID: "user-1", Name: "States",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	item, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-intent-states",
		Dimension: "文件上传",
		Technique: "upload",
		Status:    "untested",
	})
	if err != nil {
		t.Fatalf("写入 Intent 失败: %v", err)
	}
	claimed, err := db.ClaimNextProjectHypothesis(ctx, "project-intent-states")
	if err != nil || claimed == nil ||
		claimed.ExecutionState != ProjectExecutionRunning {
		t.Fatalf("领取 Intent 状态错误: %+v err=%v", claimed, err)
	}
	if affected, err := db.PauseRunningProjectHypotheses(
		ctx,
		"project-intent-states",
		"pause",
	); err != nil || affected != 1 {
		t.Fatalf("暂停 Intent 失败: affected=%d err=%v", affected, err)
	}
	paused, err := db.GetProjectTestResultByID(ctx, "project-intent-states", item.ID)
	if err != nil || paused.ExecutionState != ProjectExecutionPaused ||
		paused.Status != "paused" || !paused.LastFinishedAt.IsZero() {
		t.Fatalf("暂停状态错误: %+v err=%v", paused, err)
	}
	if affected, err := db.ResumePausedProjectHypotheses(ctx, "project-intent-states"); err != nil || affected != 1 {
		t.Fatalf("恢复 Intent 失败: affected=%d err=%v", affected, err)
	}
	resumed, err := db.GetProjectTestResultByID(ctx, "project-intent-states", item.ID)
	if err != nil || resumed.ExecutionState != ProjectExecutionOpen ||
		resumed.Status != "untested" {
		t.Fatalf("恢复状态错误: %+v err=%v", resumed, err)
	}
	if _, err := db.ClaimNextProjectHypothesis(ctx, "project-intent-states"); err != nil {
		t.Fatalf("重新领取 Intent 失败: %v", err)
	}
	if affected, err := db.StopRunningProjectHypotheses(
		ctx,
		"project-intent-states",
		"stop",
	); err != nil || affected != 1 {
		t.Fatalf("停止 Intent 失败: affected=%d err=%v", affected, err)
	}
	stopped, err := db.GetProjectTestResultByID(ctx, "project-intent-states", item.ID)
	if err != nil || stopped.ExecutionState != ProjectExecutionStopped ||
		stopped.Status != "stopped" || stopped.LastFinishedAt.IsZero() {
		t.Fatalf("停止状态错误: %+v err=%v", stopped, err)
	}
}

func TestResumePausedProjectHypothesesFiltersByReason(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-intent-reason.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-intent-reason", OwnerUserID: "user-1", Name: "Reason",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []ProjectTestResult{
		{
			ProjectID: "project-intent-reason", Dimension: "项目暂停", Technique: "project",
			Status: "paused", StateReason: "[project_pause] 项目已暂停",
		},
		{
			ProjectID: "project-intent-reason", Dimension: "用户暂停", Technique: "manual",
			Status: "paused", StateReason: "用户暂停",
		},
	} {
		if _, err := db.UpsertProjectTestResult(ctx, item); err != nil {
			t.Fatalf("创建暂停假设失败: %v", err)
		}
	}
	affected, err := db.ResumePausedProjectHypotheses(
		ctx,
		"project-intent-reason",
		"[project_pause]",
	)
	if err != nil || affected != 1 {
		t.Fatalf("应只恢复项目暂停假设: affected=%d err=%v", affected, err)
	}
	restored, err := db.ListProjectHypotheses(ctx, "project-intent-reason", "untested", 10)
	if err != nil || len(restored) != 1 || restored[0].Dimension != "项目暂停" {
		t.Fatalf("项目暂停假设未恢复: %+v err=%v", restored, err)
	}
	manual, err := db.ListProjectHypotheses(ctx, "project-intent-reason", "paused", 10)
	if err != nil || len(manual) != 1 || manual[0].Dimension != "用户暂停" {
		t.Fatalf("用户暂停假设不应恢复: %+v err=%v", manual, err)
	}
}

func TestDeleteProjectCleansTestResults(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test-results-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-delete-tests", OwnerUserID: "user-1", Name: "删除测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-delete-tests", AssetID: "asset-1",
		Dimension: "SQL注入", Status: "tested_clean",
		Result: "无差异", Evidence: "响应一致", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if err := db.DeleteProject(ctx, "project-delete-tests", "user-1"); err != nil {
		t.Fatalf("删除项目失败: %v", err)
	}
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results WHERE project_id = ?`,
		"project-delete-tests",
	).Scan(&count); err != nil {
		t.Fatalf("查询测试结果失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("删除项目后测试结果未清理: %d", count)
	}
}

func TestVulnerabilityFingerprintStableAcrossTitles(t *testing.T) {
	base := Vulnerability{
		ProjectID:         "project-1",
		AssetID:           "asset-1",
		Target:            "https://EXAMPLE.com/login?id=1&user=admin#fragment",
		VulnerabilityType: "SQL Injection",
	}
	first := VulnerabilityFingerprint(base)
	base.Title = "另一个标题"
	base.Target = "https://example.com/login?user=admin&id=1"
	second := VulnerabilityFingerprint(base)
	if first == "" || first != second {
		t.Fatalf("相同目标和漏洞类型应生成稳定指纹: %s != %s", first, second)
	}
	base.VulnerabilityType = "XSS"
	if VulnerabilityFingerprint(base) == first {
		t.Fatalf("不同漏洞类型不应生成相同指纹")
	}
}

func TestVulnerabilityEvidenceValidation(t *testing.T) {
	item := Vulnerability{
		Target:            "https://a.com/x?id=1",
		Severity:          "high",
		ReproductionSteps: "```http\nGET /x?id=1%20AND%201=1 HTTP/1.1\nHost: a.com\n```\n\n```python\nimport requests\nprint(requests.get('https://a.com/x?id=1', timeout=10).status_code)\n```",
		Evidence:          "脚本返回数据库报错：syntax error near 1=1",
		EvidenceRefs:      []string{"tool:sqlmap-1"},
		VerificationState: "verified",
	}
	if err := ValidateVulnerabilityEvidence(item); err != nil {
		t.Fatalf("完整证据应通过校验: %v", err)
	}
	item.EvidenceRefs = nil
	item.Evidence = ""
	if err := ValidateVulnerabilityEvidence(item); err == nil {
		t.Fatalf("无证据应校验失败")
	}
	item.Evidence = "HTTP 差异"
	item.ReproductionSteps = ""
	if err := ValidateVulnerabilityEvidence(item); err == nil {
		t.Fatalf("高危漏洞缺少 POC 应校验失败")
	}
}

func TestProjectHypothesesClaimAndResumeAreConversationScoped(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "conversation-scoped-hypotheses.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-scoped-claim", OwnerUserID: "user-1", Name: "会话任务隔离",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []ProjectTestResult{
		{
			ProjectID: "project-scoped-claim", AssetID: "asset-a",
			Dimension: "会话 A 任务", Technique: "a", Status: "untested",
			Priority: 90, OriginConversationID: "conv-a", CreatedAt: now,
		},
		{
			ProjectID: "project-scoped-claim", AssetID: "asset-b",
			Dimension: "会话 B 任务", Technique: "b", Status: "untested",
			Priority: 80, OriginConversationID: "conv-b", CreatedAt: now,
		},
		{
			ProjectID: "project-scoped-claim", AssetID: "asset-legacy",
			Dimension: "历史遗留任务", Technique: "legacy", Status: "untested",
			Priority: 70, CreatedAt: now,
		},
	} {
		if _, err := db.UpsertProjectTestResult(ctx, item); err != nil {
			t.Fatalf("创建会话任务失败: %v", err)
		}
	}
	first, err := db.ClaimNextProjectHypothesisForConversation(
		ctx,
		"project-scoped-claim",
		"conv-a",
	)
	if err != nil || first == nil || first.OriginConversationID != "conv-a" {
		t.Fatalf("应只领取当前会话任务: item=%+v err=%v", first, err)
	}
	second, err := db.ClaimNextProjectHypothesisForConversation(
		ctx,
		"project-scoped-claim",
		"conv-b",
	)
	if err != nil || second == nil || second.OriginConversationID != "conv-b" {
		t.Fatalf("其他会话应领取自己的任务: item=%+v err=%v", second, err)
	}
	if legacy, err := db.ClaimNextProjectHypothesisForConversation(
		ctx,
		"project-scoped-claim",
		"conv-new",
	); err != nil || legacy != nil {
		t.Fatalf("新会话不应自动领取历史任务: item=%+v err=%v", legacy, err)
	}
	reassigned, err := db.ReassignActiveProjectHypothesesToConversation(
		ctx,
		"project-scoped-claim",
		"conv-new",
		"run-new",
	)
	if err != nil || reassigned != 1 {
		t.Fatalf("显式恢复应接管历史未完成任务: count=%d err=%v", reassigned, err)
	}
	legacy, err := db.ClaimNextProjectHypothesisForConversation(
		ctx,
		"project-scoped-claim",
		"conv-new",
	)
	if err != nil || legacy == nil ||
		legacy.OriginConversationID != "conv-new" ||
		legacy.OriginRunID != "run-new" {
		t.Fatalf("恢复后的历史任务归属错误: item=%+v err=%v", legacy, err)
	}
}

func TestDeletedConversationWorkCanBeReassignedWithoutStealingLiveWork(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "orphan-hypothesis-handoff.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-orphan-handoff", OwnerUserID: "user-1", Name: "会话接管",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateProject(ctx, Project{
		ID: "project-orphan-other", OwnerUserID: "user-2", Name: "其他项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-orphan-other", OwnerUserID: "user-2", ProjectID: "project-orphan-other",
		Title: "其他会话", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他会话失败: %v", err)
	}
	for _, conversationID := range []string{
		"conv-deleted-source",
		"conv-live-source",
		"conv-orphan-target",
	} {
		if err := db.CreateConversation(ctx, Conversation{
			ID: conversationID, OwnerUserID: "user-1", ProjectID: "project-orphan-handoff",
			Title: conversationID, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("创建会话 %s 失败: %v", conversationID, err)
		}
	}
	orphaned, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-orphan-handoff", Dimension: "已删除会话任务", Technique: "orphan",
		Status: "running", ExecutionState: ProjectExecutionRunning,
		OriginConversationID: "conv-deleted-source", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建孤儿任务失败: %v", err)
	}
	live, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-orphan-handoff", Dimension: "正常会话任务", Technique: "live",
		Status: "running", ExecutionState: ProjectExecutionRunning,
		OriginConversationID: "conv-live-source", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建正常会话任务失败: %v", err)
	}
	legacyPaused, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-orphan-handoff", Dimension: "人工暂停历史任务", Technique: "legacy-paused",
		Status: "paused", ExecutionState: ProjectExecutionPaused,
		StateReason: "人工暂停", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建历史暂停任务失败: %v", err)
	}
	if _, err := db.DeleteConversations(ctx, []string{"conv-deleted-source"}, "user-1"); err != nil {
		t.Fatalf("删除来源会话失败: %v", err)
	}
	if _, err := db.ReassignOrphanedProjectHypothesesToConversation(
		ctx,
		"project-orphan-handoff",
		"conv-orphan-other",
		"user-1",
		"run-invalid",
	); err == nil {
		t.Fatal("跨项目和用户的会话不应接管项目任务")
	}
	handoff, err := db.ReassignOrphanedProjectHypothesesToConversation(
		ctx,
		"project-orphan-handoff",
		"conv-orphan-target",
		"user-1",
		"run-orphan-target",
	)
	if err != nil || handoff.Count != 1 ||
		len(handoff.SourceConversationIDs) != 1 ||
		handoff.SourceConversationIDs[0] != "conv-deleted-source" {
		t.Fatalf("孤儿任务接管结果错误: %+v err=%v", handoff, err)
	}
	current, err := db.GetProjectTestResultByID(ctx, "project-orphan-handoff", orphaned.ID)
	if err != nil || current == nil ||
		current.OriginConversationID != "conv-orphan-target" ||
		current.OriginRunID != "run-orphan-target" ||
		current.Status != "untested" ||
		current.ExecutionState != ProjectExecutionOpen {
		t.Fatalf("孤儿任务未恢复并可接管: %+v err=%v", current, err)
	}
	liveCurrent, err := db.GetProjectTestResultByID(ctx, "project-orphan-handoff", live.ID)
	if err != nil || liveCurrent == nil ||
		liveCurrent.OriginConversationID != "conv-live-source" ||
		liveCurrent.Status != "running" {
		t.Fatalf("正常会话任务不应被抢占: %+v err=%v", liveCurrent, err)
	}
	legacyCurrent, err := db.GetProjectTestResultByID(
		ctx,
		"project-orphan-handoff",
		legacyPaused.ID,
	)
	if err != nil || legacyCurrent == nil ||
		legacyCurrent.OriginConversationID != "" ||
		legacyCurrent.Status != "paused" {
		t.Fatalf("空归属历史暂停任务不应被新会话自动恢复: %+v err=%v", legacyCurrent, err)
	}
}
