package database

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProjectAssetWorkClaimsOnlyAuthorizedAssets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-work.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-work",
		OwnerUserID: "user-1",
		Name:        "资产队列",
		Scope:       "example.com",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []Asset{
		{
			ID: "asset-authorized", ProjectID: "project-work", OwnerUserID: "user-1",
			Name: "授权资产", Kind: "domain", Value: "example.com", Status: "active",
			Source: AssetSourceManual, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-discovered", ProjectID: "project-work", OwnerUserID: "user-1",
			Name: "外部资产", Kind: "domain", Value: "outside.example.net", Status: "active",
			Source: AssetSourceAgent, CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if err := db.SyncProjectAssetWork(ctx, "project-work", "user-1"); err != nil {
		t.Fatalf("同步资产队列失败: %v", err)
	}
	work, err := db.ListProjectAssetWork(ctx, "project-work", "user-1")
	if err != nil {
		t.Fatalf("读取资产队列失败: %v", err)
	}
	if len(work) != 2 {
		t.Fatalf("资产工作项数量错误: %+v", work)
	}
	authorized, err := db.GetProjectAssetWork(ctx, "project-work", "user-1", "asset-authorized")
	if err != nil || authorized == nil || authorized.AuthorizationState != AssetAuthorizationAuthorized {
		t.Fatalf("授权资产状态错误: %+v err=%v", authorized, err)
	}
	discovered, err := db.GetProjectAssetWork(ctx, "project-work", "user-1", "asset-discovered")
	if err != nil || discovered == nil || discovered.AuthorizationState != AssetAuthorizationDiscovered {
		t.Fatalf("外部资产状态错误: %+v err=%v", discovered, err)
	}

	claimed, err := db.ClaimNextProjectAssetWork(
		ctx,
		"project-work",
		"user-1",
		"conv-1",
		"run-1",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("领取资产失败: %v", err)
	}
	if claimed == nil || claimed.AssetID != "asset-authorized" || claimed.WorkState != AssetWorkActive {
		t.Fatalf("领取结果错误: %+v", claimed)
	}
	second, err := db.ClaimNextProjectAssetWork(
		ctx,
		"project-work",
		"user-1",
		"conv-2",
		"run-2",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("第二次领取失败: %v", err)
	}
	if second != nil {
		t.Fatalf("已租出的授权资产不应被重复领取: %+v", second)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work SET lease_until = ? WHERE project_id = ? AND asset_id = ?`,
		now.Add(-time.Minute).Unix(),
		"project-work",
		"asset-authorized",
	); err != nil {
		t.Fatalf("模拟租约过期失败: %v", err)
	}
	third, err := db.ClaimNextProjectAssetWork(
		ctx,
		"project-work",
		"user-1",
		"conv-2",
		"run-2",
		time.Minute,
	)
	if err != nil {
		t.Fatalf("过期租约后的领取失败: %v", err)
	}
	if third == nil || third.AssetID != "asset-authorized" {
		t.Fatalf("过期租约应允许重新领取: %+v", third)
	}
	if err := db.ReleaseProjectAssetWork(
		ctx,
		"project-work",
		"user-1",
		"asset-authorized",
		"conv-2",
		AssetWorkNeedsFollowup,
		"需要补充证据",
	); err != nil {
		t.Fatalf("释放资产失败: %v", err)
	}
}

func TestProjectAssetWorkCanSkipDeferredAsset(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-work-skip.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-work-skip", OwnerUserID: "user-1", Name: "资产跳过",
		Scope: "first.example.com\nsecond.example.com", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []Asset{
		{
			ID: "asset-first", ProjectID: "project-work-skip", OwnerUserID: "user-1",
			Name: "首个资产", Kind: "domain", Value: "first.example.com", Status: "active",
			Source: AssetSourceScope, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-second", ProjectID: "project-work-skip", OwnerUserID: "user-1",
			Name: "第二个资产", Kind: "domain", Value: "second.example.com", Status: "active",
			Source: AssetSourceScope, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if err := db.SyncProjectAssetWork(ctx, "project-work-skip", "user-1"); err != nil {
		t.Fatalf("同步资产队列失败: %v", err)
	}
	claimed, err := db.ClaimNextProjectAssetWorkExcluding(
		ctx,
		"project-work-skip",
		"user-1",
		"conv-skip",
		"run-skip",
		time.Minute,
		[]string{"asset-first"},
	)
	if err != nil {
		t.Fatalf("跳过资产后领取失败: %v", err)
	}
	if claimed == nil || claimed.AssetID != "asset-second" {
		t.Fatalf("应跳过已延迟资产并领取下一项: %+v", claimed)
	}
}

func TestAssetCloseoutRequiresCoveredTests(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-closeout.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-closeout",
		OwnerUserID: "user-1",
		Name:        "关闭门禁",
		Scope:       "example.com",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-closeout", ProjectID: "project-closeout", OwnerUserID: "user-1",
		Name: "主站", Kind: "url", Value: "https://example.com", Status: "active",
		Source: AssetSourceManual, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-closeout",
		AssetID:   "asset-closeout",
		Dimension: "登录鉴权",
		Technique: "未登录访问",
		Status:    "untested",
		Priority:  80,
		Required:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试失败: %v", err)
	}
	status, err := db.AssetCloseoutStatus(ctx, "project-closeout", "user-1", "asset-closeout")
	if err != nil {
		t.Fatalf("读取关闭门禁失败: %v", err)
	}
	if status.CanClose {
		t.Fatalf("未完成测试不应允许关闭: %+v", status)
	}
	items, err := db.ListProjectTestResultsByAsset(ctx, "project-closeout", "asset-closeout", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("读取测试失败: %+v err=%v", items, err)
	}
	items[0].Status = "tested_clean"
	items[0].ExecutionState = ProjectExecutionDone
	items[0].OutcomeState = ProjectOutcomeClean
	items[0].Evidence = "未登录请求返回 403"
	items[0].UpdatedAt = time.Now().UTC()
	if _, err := db.UpsertProjectTestResult(ctx, items[0]); err != nil {
		t.Fatalf("更新测试失败: %v", err)
	}
	status, err = db.AssetCloseoutStatus(ctx, "project-closeout", "user-1", "asset-closeout")
	if err != nil {
		t.Fatalf("重新读取关闭门禁失败: %v", err)
	}
	if !status.CanClose {
		t.Fatalf("覆盖完成的资产应允许关闭: %+v", status)
	}
}

func TestAssetCloseoutUsesAggregateEvidenceBeyondListLimit(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-closeout-aggregate.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-closeout-aggregate", OwnerUserID: "user-1", Name: "聚合门禁",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-closeout-aggregate", ProjectID: "project-closeout-aggregate",
		OwnerUserID: "user-1", Name: "聚合资产", Kind: "url",
		Value: "https://aggregate.example.com", Status: "active",
		Source: AssetSourceManual, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-closeout-aggregate", AssetID: "asset-closeout-aggregate",
		Dimension: "登录鉴权", Technique: "未登录访问", Status: "tested_clean",
		Required: true, Evidence: "匿名请求返回 403", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	for index := 0; index < 500; index++ {
		if err := db.CreateVulnerability(ctx, Vulnerability{
			ID:        fmt.Sprintf("aggregate-finding-%03d", index),
			ProjectID: "project-closeout-aggregate", AssetID: "asset-closeout-aggregate",
			OwnerUserID: "user-1", Title: "有证据漏洞", Severity: "medium",
			Status: "confirmed", Target: "https://aggregate.example.com/item?id=1",
			Evidence:  "参数化请求返回固定响应，注入表达式未改变结果",
			CreatedAt: now, UpdatedAt: now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("创建第 %d 个漏洞失败: %v", index, err)
		}
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "aggregate-missing-evidence", ProjectID: "project-closeout-aggregate",
		AssetID: "asset-closeout-aggregate", OwnerUserID: "user-1",
		Title: "缺少证据漏洞", Severity: "medium", Status: "confirmed",
		Target:    "https://aggregate.example.com/item?id=2",
		CreatedAt: now, UpdatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("创建缺证据漏洞失败: %v", err)
	}
	status, err := db.AssetCloseoutStatus(
		ctx,
		"project-closeout-aggregate",
		"user-1",
		"asset-closeout-aggregate",
	)
	if err != nil {
		t.Fatalf("读取关闭门禁失败: %v", err)
	}
	if status.CanClose || status.EvidenceGaps == 0 {
		t.Fatalf("超过列表上限的缺证据漏洞仍应阻断关闭: %+v", status)
	}
}

func TestStopProjectAssetWorkClosesUnfinishedIntentsAndTests(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-user-stop.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-user-stop", OwnerUserID: "user-1", Name: "用户停止资产",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-user-stop", ProjectID: "project-user-stop", OwnerUserID: "user-1",
		Name: "停止目标", Kind: "url", Value: "https://stop.example.com",
		Status: "active", Source: AssetSourceManual, Criticality: "high",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for _, node := range []GraphNode{
		{ID: "intent-stop-open", ProjectID: "project-user-stop", Kind: "intent", Title: "待办", Status: "open", AssetID: "asset-user-stop", CreatedAt: now, UpdatedAt: now},
		{ID: "intent-stop-running", ProjectID: "project-user-stop", Kind: "intent", Title: "运行中", Status: "running", AssetID: "asset-user-stop", CreatedAt: now, UpdatedAt: now},
		{ID: "intent-stop-done", ProjectID: "project-user-stop", Kind: "intent", Title: "已完成", Status: "done", AssetID: "asset-user-stop", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateProjectGraphNode(ctx, node); err != nil {
			t.Fatalf("创建意图失败: %v", err)
		}
	}
	for _, item := range []ProjectTestResult{
		{ID: "test-stop-untested", ProjectID: "project-user-stop", AssetID: "asset-user-stop", Dimension: "待办测试", Technique: "http", Status: "untested", IntentID: "intent-stop-open", CreatedAt: now, UpdatedAt: now},
		{ID: "test-stop-running", ProjectID: "project-user-stop", AssetID: "asset-user-stop", Dimension: "运行测试", Technique: "http", Status: "running", IntentID: "intent-stop-running", CreatedAt: now, UpdatedAt: now},
		{ID: "test-stop-clean", ProjectID: "project-user-stop", AssetID: "asset-user-stop", Dimension: "已完成测试", Technique: "http", Status: "tested_clean", Evidence: "HTTP 200", IntentID: "intent-stop-done", CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := db.UpsertProjectTestResult(ctx, item); err != nil {
			t.Fatalf("创建测试结果失败: %v", err)
		}
	}
	if err := db.SyncProjectAssetWork(ctx, "project-user-stop", "user-1"); err != nil {
		t.Fatalf("同步资产工作项失败: %v", err)
	}
	result, err := db.StopProjectAssetWork(
		ctx,
		"project-user-stop",
		"user-1",
		"asset-user-stop",
		"用户停止资产探测",
	)
	if err != nil {
		t.Fatalf("停止资产失败: %v", err)
	}
	if result.StoppedIntents != 2 || result.StoppedTests != 2 {
		t.Fatalf("停止数量错误: %+v", result)
	}
	work, err := db.GetProjectAssetWork(ctx, "project-user-stop", "user-1", "asset-user-stop")
	if err != nil || work == nil || work.WorkState != AssetWorkBlocked ||
		!strings.Contains(work.StateReason, "用户停止资产探测") {
		t.Fatalf("资产工作项未停止: %+v err=%v", work, err)
	}
	for _, intentID := range []string{"intent-stop-open", "intent-stop-running"} {
		node, err := db.GetProjectGraphNode(ctx, intentID, "project-user-stop")
		if err != nil || node.Status != "stopped" || !strings.Contains(node.Detail, "用户停止资产探测") {
			t.Fatalf("意图未停止: %+v err=%v", node, err)
		}
	}
	done, err := db.GetProjectGraphNode(ctx, "intent-stop-done", "project-user-stop")
	if err != nil || done.Status != "done" {
		t.Fatalf("已完成意图不应被改写: %+v err=%v", done, err)
	}
	for _, testID := range []string{"test-stop-untested", "test-stop-running"} {
		item, err := db.GetProjectTestResultByID(ctx, "project-user-stop", testID)
		if err != nil || item.Status != "stopped" || item.StateReason != AssetUserStopReason {
			t.Fatalf("测试结果未停止: %+v err=%v", item, err)
		}
	}
	clean, err := db.GetProjectTestResultByID(ctx, "project-user-stop", "test-stop-clean")
	if err != nil || clean.Status != "tested_clean" {
		t.Fatalf("已完成测试不应被改写: %+v err=%v", clean, err)
	}
	if _, err := db.StopProjectAssetWork(
		ctx,
		"project-user-stop",
		"user-1",
		"asset-user-stop",
		"重复停止",
	); !errors.Is(err, ErrAssetWorkNotStoppable) {
		t.Fatalf("已停止资产不应重复停止: %v", err)
	}
}
