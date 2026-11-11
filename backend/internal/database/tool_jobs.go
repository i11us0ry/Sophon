package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"sophon/internal/redact"
)

const (
	ToolJobStatusRunning     = "running"
	ToolJobStatusCompleted   = "completed"
	ToolJobStatusFailed      = "failed"
	ToolJobStatusCancelled   = "cancelled"
	ToolJobStatusInterrupted = "interrupted"
)

type ToolJob struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversationId"`
	UserID         string                 `json:"userId"`
	AgentID        string                 `json:"agentId"`
	DedupKey       string                 `json:"dedupKey"`
	Status         string                 `json:"status"`
	Steps          []string               `json:"steps"`
	NextStep       int                    `json:"nextStep"`
	Progress       map[string]interface{} `json:"progress"`
	Result         string                 `json:"result"`
	Error          string                 `json:"error"`
	CreatedAt      time.Time              `json:"createdAt"`
	UpdatedAt      time.Time              `json:"updatedAt"`
	FinishedAt     *time.Time             `json:"finishedAt,omitempty"`
}

func (db *DB) CreateToolJob(ctx context.Context, item ToolJob) (*ToolJob, bool, error) {
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.UserID = strings.TrimSpace(item.UserID)
	item.AgentID = strings.TrimSpace(item.AgentID)
	item.DedupKey = strings.TrimSpace(item.DedupKey)
	item.Status = strings.TrimSpace(item.Status)
	if item.ConversationID == "" || item.UserID == "" || item.DedupKey == "" {
		return nil, false, fmt.Errorf("Job 会话、用户和去重键不能为空")
	}
	if item.Status == "" {
		item.Status = ToolJobStatusRunning
	}
	if len(item.Steps) == 0 {
		return nil, false, fmt.Errorf("Job 至少需要一个执行步骤")
	}
	if item.Progress == nil {
		item.Progress = map[string]interface{}{}
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	stepsJSON, err := json.Marshal(item.Steps)
	if err != nil {
		return nil, false, err
	}
	encryptedSteps, err := db.encryptJobSteps(string(stepsJSON))
	if err != nil {
		return nil, false, err
	}
	progressJSON, err := json.Marshal(sanitizeJobValue(item.Progress))
	if err != nil {
		return nil, false, err
	}
	result, err := db.ExecContext(
		ctx,
		`INSERT INTO tool_jobs (
			id, conversation_id, user_id, agent_id, dedup_key, status,
			steps_json, next_step, progress_json, result, error, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(conversation_id, user_id, dedup_key) DO NOTHING`,
		item.ID,
		item.ConversationID,
		item.UserID,
		item.AgentID,
		item.DedupKey,
		item.Status,
		encryptedSteps,
		item.NextStep,
		string(progressJSON),
		item.Result,
		item.Error,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return nil, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, false, err
	}
	if affected == 1 {
		return &item, true, nil
	}
	existing, err := db.GetToolJobByDedupKey(ctx, item.ConversationID, item.UserID, item.DedupKey)
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

func (db *DB) GetToolJob(ctx context.Context, id, userID string) (*ToolJob, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, agent_id, dedup_key, status,
		        steps_json, next_step, progress_json, result, error,
		        created_at, updated_at, coalesce(finished_at, 0)
		 FROM tool_jobs
		 WHERE id = ? AND user_id = ?`,
		strings.TrimSpace(id),
		strings.TrimSpace(userID),
	)
	return db.scanToolJob(row)
}

func (db *DB) GetToolJobByDedupKey(
	ctx context.Context,
	conversationID string,
	userID string,
	dedupKey string,
) (*ToolJob, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, agent_id, dedup_key, status,
		        steps_json, next_step, progress_json, result, error,
		        created_at, updated_at, coalesce(finished_at, 0)
		 FROM tool_jobs
		 WHERE conversation_id = ? AND user_id = ? AND dedup_key = ?`,
		strings.TrimSpace(conversationID),
		strings.TrimSpace(userID),
		strings.TrimSpace(dedupKey),
	)
	return db.scanToolJob(row)
}

func (db *DB) FindRunningToolJobByAgent(
	ctx context.Context,
	conversationID string,
	userID string,
	agentID string,
	excludeID string,
) (*ToolJob, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, agent_id, dedup_key, status,
		        steps_json, next_step, progress_json, result, error,
		        created_at, updated_at, coalesce(finished_at, 0)
		 FROM tool_jobs
		 WHERE conversation_id = ? AND user_id = ? AND agent_id = ?
		   AND status = ? AND id <> ?
		 ORDER BY updated_at DESC
		 LIMIT 1`,
		strings.TrimSpace(conversationID),
		strings.TrimSpace(userID),
		strings.TrimSpace(agentID),
		ToolJobStatusRunning,
		strings.TrimSpace(excludeID),
	)
	item, err := db.scanToolJob(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return item, err
}

func (db *DB) UpdateToolJob(
	ctx context.Context,
	id string,
	userID string,
	expectedStatuses []string,
	status string,
	nextStep int,
	progress map[string]interface{},
	result string,
	errText string,
	finished bool,
) (bool, error) {
	expected := make([]string, 0, len(expectedStatuses))
	seen := map[string]bool{}
	for _, value := range expectedStatuses {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		expected = append(expected, value)
	}
	if len(expected) == 0 {
		return false, fmt.Errorf("Job 状态迁移必须指定期望状态")
	}
	if progress == nil {
		progress = map[string]interface{}{}
	}
	rawProgress, err := json.Marshal(sanitizeJobValue(progress))
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	var finishedAt interface{}
	if finished {
		finishedAt = now.Unix()
	}
	queryArgs := []interface{}{
		strings.TrimSpace(status),
		nextStep,
		string(rawProgress),
		redact.Text(result),
		redact.Text(errText),
		now.Unix(),
		finishedAt,
		strings.TrimSpace(id),
		strings.TrimSpace(userID),
	}
	queryArgs = append(queryArgs, buildIDArgs(nil, expected)...)
	res, err := db.ExecContext(
		ctx,
		`UPDATE tool_jobs
		 SET status = ?, next_step = ?, progress_json = ?, result = ?, error = ?,
		     updated_at = ?, finished_at = ?
		 WHERE id = ? AND user_id = ? AND status IN (`+placeholders(len(expected))+`)`,
		queryArgs...,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func sanitizeJobValue(value any) any {
	switch typed := value.(type) {
	case string:
		return redact.Text(typed)
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			out[key] = sanitizeJobValue(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for index, item := range typed {
			out[index] = sanitizeJobValue(item)
		}
		return out
	case []string:
		out := make([]string, len(typed))
		for index, item := range typed {
			out[index] = redact.Text(item)
		}
		return out
	default:
		return value
	}
}

func (db *DB) InterruptRunningToolJobs(ctx context.Context, reason string) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "服务重启导致 Job 中断，可调用 job(action=resume) 从检查点继续"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE tool_jobs
		 SET status = ?, error = ?, updated_at = ?, finished_at = ?
		 WHERE status = ?`,
		ToolJobStatusInterrupted,
		reason,
		now.Unix(),
		now.Unix(),
		ToolJobStatusRunning,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

type toolJobScanner interface {
	Scan(dest ...interface{}) error
}

func (db *DB) scanToolJob(row toolJobScanner) (*ToolJob, error) {
	var item ToolJob
	var stepsJSON, progressJSON string
	var createdAt, updatedAt, finishedAt int64
	if err := row.Scan(
		&item.ID,
		&item.ConversationID,
		&item.UserID,
		&item.AgentID,
		&item.DedupKey,
		&item.Status,
		&stepsJSON,
		&item.NextStep,
		&progressJSON,
		&item.Result,
		&item.Error,
		&createdAt,
		&updatedAt,
		&finishedAt,
	); err != nil {
		return nil, err
	}
	decryptedSteps, err := db.decryptJobSteps(stepsJSON)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(decryptedSteps), &item.Steps); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(progressJSON), &item.Progress); err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	if finishedAt > 0 {
		finished := time.Unix(finishedAt, 0).UTC()
		item.FinishedAt = &finished
	}
	return &item, nil
}
