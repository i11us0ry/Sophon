package database

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartToolExecutionRedactsArguments(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	db.StartToolExecution(ctx, "conv-1", "user-1", "exec", map[string]interface{}{
		"command":  "curl",
		"password": "plain-secret",
		"apiKey":   "sk-secret",
		"nested":   map[string]interface{}{"token": "nested-token-value"},
	})

	items, err := db.ListToolExecutions(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("读取工具执行失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("应写入 1 条执行记录，实际 %d", len(items))
	}
	raw, err := json.Marshal(items[0].Arguments)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	text := string(raw)
	for _, secret := range []string{"plain-secret", "sk-secret", "nested-token-value"} {
		if strings.Contains(text, secret) {
			t.Fatalf("工具参数未脱敏：%s", text)
		}
	}
	if !strings.Contains(text, "curl") {
		t.Fatalf("普通参数应保留：%s", text)
	}
	firstFingerprint := ToolExecutionFingerprint(map[string]interface{}{"password": "one"})
	secondFingerprint := ToolExecutionFingerprint(map[string]interface{}{"password": "two"})
	if firstFingerprint == "" || firstFingerprint == secondFingerprint {
		t.Fatalf("不同敏感参数必须生成不同指纹")
	}
}

func TestFindRecentCompletedToolExecutionByFingerprint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "probe-dedupe.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	args := map[string]interface{}{
		"command": `curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json`,
	}
	id := db.StartToolExecution(ctx, "conv-probe", "user-1", "exec", args)
	db.FinishToolExecution(ctx, id, `{"code":0}`, nil)

	item, err := db.FindRecentCompletedToolExecution(
		ctx,
		"conv-probe",
		"exec",
		ToolExecutionFingerprint(args),
		time.Now().UTC().Add(-time.Minute),
	)
	if err != nil || item == nil || item.ID != id || item.Result != `{"code":0}` {
		t.Fatalf("未命中最近完成探测: item=%+v err=%v", item, err)
	}
	if other, err := db.FindRecentCompletedToolExecution(
		ctx,
		"other-conversation",
		"exec",
		ToolExecutionFingerprint(args),
		time.Now().UTC().Add(-time.Minute),
	); err != nil || other != nil {
		t.Fatalf("探测去重不应跨会话命中: item=%+v err=%v", other, err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE tool_executions SET fingerprint = '' WHERE id = ?`, id); err != nil {
		t.Fatalf("模拟旧记录失败: %v", err)
	}
	legacy, err := db.FindRecentCompletedToolExecution(
		ctx,
		"conv-probe",
		"exec",
		ToolExecutionFingerprint(args),
		time.Now().UTC().Add(-time.Minute),
	)
	if err != nil || legacy == nil || legacy.ID != id {
		t.Fatalf("旧记录指纹回退失败: item=%+v err=%v", legacy, err)
	}
}

func TestListRecentProbeExecutionsFiltersToolAndConversation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "probe-ledger.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	execID := db.StartToolExecution(ctx, "conv-ledger", "user-1", "exec", map[string]interface{}{
		"command": "curl https://falcon.example.com/rc_oa_gateway/user/session.json",
	})
	db.FinishToolExecution(ctx, execID, "200", nil)
	projectID := db.StartToolExecution(ctx, "conv-ledger", "user-1", "project_list_facts", map[string]interface{}{})
	db.FinishToolExecution(ctx, projectID, "facts", nil)
	otherID := db.StartToolExecution(ctx, "conv-other", "user-1", "exec", map[string]interface{}{
		"command": "curl https://example.com/",
	})
	db.FinishToolExecution(ctx, otherID, "200", nil)

	items, err := db.ListRecentProbeExecutions(
		ctx,
		"conv-ledger",
		time.Now().UTC().Add(-time.Minute),
		10,
	)
	if err != nil {
		t.Fatalf("读取探测账本失败: %v", err)
	}
	if len(items) != 1 || items[0].ID != execID || items[0].ToolName != "exec" {
		t.Fatalf("探测账本筛选异常: %+v", items)
	}
}

func TestListRecentFailedToolExecutionsFiltersConversation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "failed-tools.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	failedID := db.StartToolExecution(ctx, "conv-1", "user-1", "nmap", map[string]interface{}{})
	db.FinishToolExecution(ctx, failedID, "", errors.New("nmap failed"))
	completedID := db.StartToolExecution(ctx, "conv-1", "user-1", "curl", map[string]interface{}{})
	db.FinishToolExecution(ctx, completedID, "ok", nil)
	otherID := db.StartToolExecution(ctx, "conv-2", "user-1", "hydra", map[string]interface{}{})
	db.FinishToolExecution(ctx, otherID, "", errors.New("hydra failed"))

	items, err := db.ListRecentFailedToolExecutions(ctx, "conv-1", 5)
	if err != nil {
		t.Fatalf("读取最近失败工具失败: %v", err)
	}
	if len(items) != 1 || items[0].ToolName != "nmap" || items[0].Error != "nmap failed" {
		t.Fatalf("失败工具筛选异常: %+v", items)
	}
}

func TestHasCompletedToolExecutionSince(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "completed-tools.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	since := time.Now().UTC().Add(-time.Second)

	has, err := db.HasCompletedToolExecutionSince(ctx, "conv-1", since)
	if err != nil || has {
		t.Fatalf("初始不应有完成证据: has=%v err=%v", has, err)
	}
	id := db.StartToolExecution(ctx, "conv-1", "user-1", "nmap", map[string]interface{}{})
	db.FinishToolExecution(ctx, id, "ok", nil)

	has, err = db.HasCompletedToolExecutionSince(ctx, "conv-1", since)
	if err != nil || !has {
		t.Fatalf("应检测到完成工具证据: has=%v err=%v", has, err)
	}
}

func TestFinishToolExecutionCapsStoredResult(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-result-limit.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	executionID := db.StartToolExecution(
		ctx,
		"conv-large-result",
		"user-1",
		"exec",
		map[string]interface{}{},
	)
	db.FinishToolExecution(
		ctx,
		executionID,
		strings.Repeat("A", maxToolExecutionResultBytes*2),
		nil,
	)
	item, err := db.GetToolExecution(ctx, executionID)
	if err != nil {
		t.Fatalf("读取工具执行失败: %v", err)
	}
	if len(item.Result) > maxToolExecutionResultBytes+128 ||
		!strings.Contains(item.Result, "已截断") {
		t.Fatalf("工具结果未按上限保存，长度=%d", len(item.Result))
	}
}

func TestFinishToolExecutionSurvivesCanceledContext(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-canceled.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	executionID := db.StartToolExecution(
		ctx,
		"conv-canceled",
		"user-1",
		"exec",
		map[string]interface{}{},
	)
	cancel()
	db.FinishToolExecution(ctx, executionID, "completed after cancel", nil)

	item, err := db.GetToolExecution(context.Background(), executionID)
	if err != nil {
		t.Fatalf("读取工具执行失败: %v", err)
	}
	if item.Status != "completed" || item.Result != "completed after cancel" {
		t.Fatalf("取消上下文不应阻止最终状态写回: %+v", item)
	}
}

func TestFailRunningToolExecutionsCleansRestartLeavings(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-running-cleanup.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	runningID := db.StartToolExecution(
		ctx,
		"conv-running",
		"user-1",
		"nmap",
		map[string]interface{}{},
	)
	completedID := db.StartToolExecution(
		ctx,
		"conv-running",
		"user-1",
		"curl",
		map[string]interface{}{},
	)
	db.FinishToolExecution(ctx, completedID, "ok", nil)

	affected, err := db.FailRunningToolExecutions(ctx, "服务重启")
	if err != nil || affected != 1 {
		t.Fatalf("清理 running 记录失败: affected=%d err=%v", affected, err)
	}
	running, err := db.GetToolExecution(ctx, runningID)
	if err != nil || running.Status != "failed" {
		t.Fatalf("遗留 running 记录未标记失败: %+v err=%v", running, err)
	}
	completed, err := db.GetToolExecution(ctx, completedID)
	if err != nil || completed.Status != "completed" {
		t.Fatalf("已完成记录不应被修改: %+v err=%v", completed, err)
	}
}
