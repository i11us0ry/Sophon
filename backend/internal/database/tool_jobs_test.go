package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolJobEncryptionKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "tool-jobs-key.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	info, err := os.Stat(filepath.Join(dir, ".sophon-job-key"))
	if err != nil {
		t.Fatalf("Job 加密密钥未创建: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Job 加密密钥权限错误: %o", info.Mode().Perm())
	}
}

func TestToolJobLifecycleAndDedupe(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-jobs.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	job, created, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-job",
		UserID:         "user-1",
		AgentID:        "sub-1",
		DedupKey:       "sub-1:scan",
		Status:         ToolJobStatusRunning,
		Steps:          []string{"scan-a", "scan-b"},
		Progress:       map[string]interface{}{"currentStep": 1},
	})
	if err != nil || !created {
		t.Fatalf("创建 Job 失败: created=%v err=%v", created, err)
	}
	var storedSteps string
	if err := db.QueryRowContext(
		ctx,
		`SELECT steps_json FROM tool_jobs WHERE id = ?`,
		job.ID,
	).Scan(&storedSteps); err != nil {
		t.Fatalf("读取 Job 步骤密文失败: %v", err)
	}
	if strings.Contains(storedSteps, "scan-a") || !strings.HasPrefix(storedSteps, jobCipherPrefix) {
		t.Fatalf("Job 步骤应以密文落库: %q", storedSteps)
	}
	if _, _, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-job",
		UserID:         "user-1",
		AgentID:        "sub-1",
		DedupKey:       "sub-1:other",
		Status:         ToolJobStatusRunning,
		Steps:          []string{"other"},
	}); err == nil {
		t.Fatalf("同一 Worker 不应并行启动第二个运行中 Job")
	}
	duplicate, created, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-job",
		UserID:         "user-1",
		AgentID:        "sub-1",
		DedupKey:       "sub-1:scan",
		Status:         ToolJobStatusRunning,
		Steps:          []string{"different"},
	})
	if err != nil || created || duplicate.ID != job.ID {
		t.Fatalf("重复 Job 应复用原记录: created=%v duplicate=%+v err=%v", created, duplicate, err)
	}
	if updated, err := db.UpdateToolJob(
		ctx,
		job.ID,
		"user-1",
		[]string{ToolJobStatusRunning},
		ToolJobStatusRunning,
		1,
		map[string]interface{}{"currentStep": 2, "lastOutput": "token=plain-secret"},
		"first done authorization=Bearer abc.def",
		"",
		false,
	); err != nil || !updated {
		t.Fatalf("更新 Job 失败: %v", err)
	}
	if updated, err := db.UpdateToolJob(
		ctx,
		job.ID,
		"user-1",
		[]string{ToolJobStatusInterrupted},
		ToolJobStatusRunning,
		1,
		map[string]interface{}{},
		"",
		"",
		false,
	); err != nil || updated {
		t.Fatalf("状态不匹配时不应更新: updated=%v err=%v", updated, err)
	}
	updated, err := db.GetToolJob(ctx, job.ID, "user-1")
	if err != nil || updated.NextStep != 1 ||
		strings.Contains(updated.Result, "abc.def") ||
		strings.Contains(updated.Result, "plain-secret") {
		t.Fatalf("Job 更新结果错误: %+v err=%v", updated, err)
	}
	if output, _ := updated.Progress["lastOutput"].(string); strings.Contains(output, "plain-secret") {
		t.Fatalf("Job 进度输出未脱敏: %q", output)
	}
	if affected, err := db.InterruptRunningToolJobs(ctx, "restart"); err != nil || affected != 1 {
		t.Fatalf("中断 Job 失败: affected=%d err=%v", affected, err)
	}
	interrupted, err := db.GetToolJob(ctx, job.ID, "user-1")
	if err != nil || interrupted.Status != ToolJobStatusInterrupted || interrupted.FinishedAt == nil {
		t.Fatalf("Job 中断状态错误: %+v err=%v", interrupted, err)
	}
}

func TestToolJobReadsLegacyPlaintextSteps(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-jobs-legacy.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	job, _, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-legacy",
		UserID:         "user-1",
		AgentID:        "sub-legacy",
		DedupKey:       "legacy",
		Status:         ToolJobStatusCompleted,
		Steps:          []string{"old"},
	})
	if err != nil {
		t.Fatalf("创建 Job 失败: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE tool_jobs SET steps_json = ? WHERE id = ?`,
		`["legacy-step"]`,
		job.ID,
	); err != nil {
		t.Fatalf("写入旧版明文 Job 失败: %v", err)
	}
	got, err := db.GetToolJob(ctx, job.ID, "user-1")
	if err != nil {
		t.Fatalf("读取旧版 Job 失败: %v", err)
	}
	if len(got.Steps) != 1 || got.Steps[0] != "legacy-step" {
		t.Fatalf("旧版 Job 步骤兼容失败: %#v", got.Steps)
	}
}

func TestToolJobMigrationEncryptsLegacySteps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool-jobs-legacy-migrate.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	ctx := context.Background()
	job, _, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-legacy-migrate",
		UserID:         "user-1",
		AgentID:        "sub-legacy",
		DedupKey:       "legacy-migrate",
		Status:         ToolJobStatusCompleted,
		Steps:          []string{"old"},
	})
	if err != nil {
		t.Fatalf("创建 Job 失败: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE tool_jobs SET steps_json = ? WHERE id = ?`,
		`["legacy-migrate-step"]`,
		job.ID,
	); err != nil {
		t.Fatalf("写回旧版明文失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatalf("重新打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var stored string
	if err := db.QueryRowContext(
		ctx,
		`SELECT steps_json FROM tool_jobs WHERE id = ?`,
		job.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("读取迁移后步骤失败: %v", err)
	}
	if strings.Contains(stored, "legacy-migrate-step") || !strings.HasPrefix(stored, jobCipherPrefix) {
		t.Fatalf("旧版步骤未在启动时加密: %q", stored)
	}
}

func TestResetRunningProjectHypotheses(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "hypothesis-recovery.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-recovery", OwnerUserID: "user-1", Name: "恢复测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	item, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-recovery",
		AssetID:   "asset-1",
		Dimension: "SQL注入",
		Status:    "running",
		Attempts:  2,
		Evidence:  "已有证据",
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建 running 假设失败: %v", err)
	}
	affected, err := db.ResetRunningProjectHypotheses(ctx, "worker interrupted")
	if err != nil || affected != 1 {
		t.Fatalf("恢复假设失败: affected=%d err=%v", affected, err)
	}
	updated, err := db.GetProjectTestResultByID(ctx, "project-recovery", item.ID)
	if err != nil {
		t.Fatalf("读取假设失败: %v", err)
	}
	if updated.Status != "untested" ||
		updated.Attempts != 2 ||
		!strings.Contains(updated.Evidence, "已有证据") ||
		!strings.Contains(updated.Evidence, "worker interrupted") {
		t.Fatalf("假设恢复状态错误: %+v", updated)
	}
}

func TestDeleteConversationRemovesToolJobs(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-jobs-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-job-delete", OwnerUserID: "user-1", Title: "删除 Job",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if _, _, err := db.CreateToolJob(ctx, ToolJob{
		ConversationID: "conv-job-delete",
		UserID:         "user-1",
		AgentID:        "sub-delete",
		DedupKey:       "delete",
		Status:         ToolJobStatusCompleted,
		Steps:          []string{"echo ok"},
	}); err != nil {
		t.Fatalf("创建 Job 失败: %v", err)
	}
	if deleted, err := db.DeleteConversations(ctx, []string{"conv-job-delete"}, "user-1"); err != nil || deleted != 1 {
		t.Fatalf("删除会话失败: deleted=%d err=%v", deleted, err)
	}
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tool_jobs WHERE conversation_id = ?`,
		"conv-job-delete",
	).Scan(&count); err != nil {
		t.Fatalf("查询 Job 失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("删除会话后 Job 残留: %d", count)
	}
}
