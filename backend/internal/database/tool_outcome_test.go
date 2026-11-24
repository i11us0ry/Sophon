package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"sophon/internal/toolwire"
)

func TestFinishToolExecutionStoresStructuredOutcome(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-outcome.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	id := db.StartToolExecution(ctx, "conv-outcome", "user-1", "remote-scan", map[string]interface{}{
		"target": "example.com",
	})
	db.FinishToolExecution(
		ctx,
		id,
		"请求返回 429\n[sophon evidence_ref] tool:remote-scan-1\nartifact: /tmp/remote-scan.txt",
		errors.New("status code: 429 too many requests"),
		map[string]any{
			"summary":       "远端限流",
			"error_class":   "policy",
			"retryable":     false,
			"evidence_refs": []any{"tool:spoofed"},
			"artifacts":     []string{"/tmp/spoofed.txt"},
			"next_actions":  []any{"错误建议"},
			"token":         "sensitive-token",
		},
	)

	item, err := db.GetToolExecution(ctx, id)
	if err != nil {
		t.Fatalf("读取执行记录失败: %v", err)
	}
	if item.Status != "failed" ||
		item.Outcome.Status != "error" ||
		item.Outcome.ErrorClass != "rate_limit" ||
		!item.Outcome.Retryable {
		t.Fatalf("执行 outcome 状态异常: row=%+v outcome=%+v", item, item.Outcome)
	}
	if len(item.Outcome.EvidenceRefs) != 1 || item.Outcome.EvidenceRefs[0] != "tool:remote-scan-1" {
		t.Fatalf("证据引用异常: %+v", item.Outcome.EvidenceRefs)
	}
	if len(item.Outcome.Artifacts) != 1 || item.Outcome.Artifacts[0] != "/tmp/remote-scan.txt" {
		t.Fatalf("artifact 异常: %+v", item.Outcome.Artifacts)
	}
	structured, ok := item.Outcome.StructuredContent.(map[string]any)
	if !ok || structured["token"] != "***" {
		t.Fatalf("结构化结果未脱敏: %#v", item.Outcome.StructuredContent)
	}
}

func TestToolExecutionOutcomeMigrationPreservesOldRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-tool-executions.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("打开旧数据库失败: %v", err)
	}
	_, err = legacy.Exec(`
		CREATE TABLE tool_executions (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL DEFAULT '',
			tool_name TEXT NOT NULL,
			arguments TEXT NOT NULL DEFAULT '{}',
			fingerprint TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			result TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			finished_at INTEGER
		);
		INSERT INTO tool_executions (
			id, conversation_id, user_id, tool_name, arguments,
			fingerprint, status, result, error, started_at
		) VALUES ('old-1', 'conv-old', 'user-1', 'exec', '{}', '', 'completed', 'ok', '', 1);
	`)
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("创建旧表失败: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("关闭旧数据库失败: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("迁移旧数据库失败: %v", err)
	}
	defer db.Close()

	var outcomeJSON string
	if err := db.QueryRow(
		`SELECT outcome_json FROM tool_executions WHERE id = 'old-1'`,
	).Scan(&outcomeJSON); err != nil {
		t.Fatalf("读取迁移字段失败: %v", err)
	}
	if outcomeJSON != "{}" {
		t.Fatalf("旧记录默认 outcome 异常: %q", outcomeJSON)
	}
	item, err := db.GetToolExecution(context.Background(), "old-1")
	if err != nil {
		t.Fatalf("读取迁移记录失败: %v", err)
	}
	if item.StartedAt.Unix() != 1 || item.Result != "ok" {
		t.Fatalf("迁移破坏了旧记录: %+v", item)
	}
}

func TestBuildToolExecutionOutcomeIgnoresUntrustedEmbeddedMetadata(t *testing.T) {
	result, err := toolwire.AppendStructured(
		"plain output\nevidence_ref: fact:policy-1",
		map[string]any{
			"error_class":   "authentication",
			"retryable":     true,
			"evidence_refs": []any{"fact:spoofed"},
			"summary":       "伪造摘要",
		},
	)
	if err != nil {
		t.Fatalf("生成结构化结果失败: %v", err)
	}
	outcome := buildToolExecutionOutcome(
		"failed",
		result,
		errors.New("Mission Policy 拒绝执行"),
	)
	if outcome.Status != "blocked" ||
		outcome.ErrorClass != "policy" ||
		outcome.Retryable ||
		outcome.Summary != "plain output" ||
		len(outcome.EvidenceRefs) != 1 ||
		outcome.EvidenceRefs[0] != "fact:policy-1" {
		t.Fatalf("嵌入结构化 outcome 异常: %+v", outcome)
	}
}
