package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"sophon/internal/redact"
)

const (
	maxToolExecutionResultBytes = 64 * 1024
	toolExecutionWriteTimeout   = 5 * time.Second
)

type ToolExecution struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversationId"`
	UserID         string                 `json:"userId"`
	ToolName       string                 `json:"toolName"`
	Arguments      map[string]interface{} `json:"arguments"`
	Fingerprint    string                 `json:"-"`
	Status         string                 `json:"status"`
	Result         string                 `json:"result"`
	Error          string                 `json:"error"`
	StartedAt      time.Time              `json:"startedAt"`
	FinishedAt     *time.Time             `json:"finishedAt"`
}

func ToolExecutionFingerprint(args map[string]interface{}) string {
	raw, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ToolExecutionFingerprintFromJSON(raw string) string {
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &args); err != nil {
		return ""
	}
	return ToolExecutionFingerprint(args)
}

func (db *DB) StartToolExecution(
	ctx context.Context,
	conversationID string,
	userID string,
	toolName string,
	args map[string]interface{},
) string {
	id := newID()
	raw, _ := json.Marshal(redact.Value(args, ""))
	fingerprint := ToolExecutionFingerprint(args)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), toolExecutionWriteTimeout)
	defer cancel()
	_, _ = db.ExecContext(
		writeCtx,
		`INSERT INTO tool_executions (
			id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at
		) VALUES (?, ?, ?, ?, ?, ?, 'running', '', '', ?)`,
		id,
		conversationID,
		userID,
		toolName,
		string(raw),
		fingerprint,
		time.Now().UTC().Unix(),
	)
	return id
}

func (db *DB) FinishToolExecution(
	ctx context.Context,
	id string,
	result string,
	invokeErr error,
) {
	if id == "" {
		return
	}
	status := "completed"
	errText := ""
	finishedAt := time.Now().UTC()
	if invokeErr != nil {
		status = "failed"
		errText = truncateToolExecutionText(redact.Text(invokeErr.Error()))
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), toolExecutionWriteTimeout)
	defer cancel()
	_, _ = db.ExecContext(
		writeCtx,
		`UPDATE tool_executions
		 SET status = ?, result = ?, error = ?, finished_at = ?
		 WHERE id = ?`,
		status,
		truncateToolExecutionText(redact.Text(result)),
		errText,
		finishedAt.Unix(),
		id,
	)
}

// FailRunningToolExecutions 清理进程重启后不可能继续运行的执行记录。
func (db *DB) FailRunningToolExecutions(
	ctx context.Context,
	reason string,
) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "服务重启导致执行中断"
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE tool_executions
		 SET status = 'failed', error = ?, finished_at = ?
		 WHERE status = 'running'`,
		reason,
		time.Now().UTC().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func truncateToolExecutionText(value string) string {
	if len(value) <= maxToolExecutionResultBytes {
		return value
	}
	cut := maxToolExecutionResultBytes
	for cut > 0 && value[cut]&0xc0 == 0x80 {
		cut--
	}
	return strings.ToValidUTF8(value[:cut], "") +
		"\n...(工具输出超过 64KB，已截断)"
}

func (db *DB) ListToolExecutions(
	ctx context.Context,
	userID string,
	limit int,
) ([]ToolExecution, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at, finished_at
		 FROM tool_executions
		 WHERE user_id = ?
		 ORDER BY started_at DESC
		 LIMIT ?`,
		userID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ToolExecution, 0)
	for rows.Next() {
		var item ToolExecution
		var raw string
		var startedAt int64
		var finishedAt interface{}
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.UserID,
			&item.ToolName,
			&raw,
			&item.Fingerprint,
			&item.Status,
			&item.Result,
			&item.Error,
			&startedAt,
			&finishedAt,
		); err != nil {
			return nil, err
		}
		item.StartedAt = time.Unix(startedAt, 0)
		_ = json.Unmarshal([]byte(raw), &item.Arguments)
		if value, ok := finishedAt.(int64); ok {
			finished := time.Unix(value, 0)
			item.FinishedAt = &finished
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetToolExecution(
	ctx context.Context,
	id string,
) (*ToolExecution, error) {
	var item ToolExecution
	var raw string
	var startedAt int64
	var finishedAt sql.NullInt64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at, finished_at
		 FROM tool_executions WHERE id = ?`,
		id,
	).Scan(
		&item.ID,
		&item.ConversationID,
		&item.UserID,
		&item.ToolName,
		&raw,
		&item.Fingerprint,
		&item.Status,
		&item.Result,
		&item.Error,
		&startedAt,
		&finishedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &item.Arguments)
	item.StartedAt = time.Unix(startedAt, 0)
	if finishedAt.Valid {
		value := time.Unix(finishedAt.Int64, 0)
		item.FinishedAt = &value
	}
	return &item, nil
}

type toolExecutionScanner interface {
	Scan(dest ...interface{}) error
}

func scanToolExecution(row toolExecutionScanner) (*ToolExecution, error) {
	var item ToolExecution
	var raw string
	var startedAt int64
	var finishedAt sql.NullInt64
	if err := row.Scan(
		&item.ID,
		&item.ConversationID,
		&item.UserID,
		&item.ToolName,
		&raw,
		&item.Fingerprint,
		&item.Status,
		&item.Result,
		&item.Error,
		&startedAt,
		&finishedAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &item.Arguments)
	item.StartedAt = time.Unix(startedAt, 0)
	if finishedAt.Valid {
		value := time.Unix(finishedAt.Int64, 0)
		item.FinishedAt = &value
	}
	return &item, nil
}

// FindRecentCompletedToolExecution 查找同一会话中参数相同且已经成功完成的工具执行。
// 对旧记录 fingerprint 为空的记录，回退到最近 100 条并即时计算指纹。
func (db *DB) FindRecentCompletedToolExecution(
	ctx context.Context,
	conversationID string,
	toolName string,
	fingerprint string,
	since time.Time,
) (*ToolExecution, error) {
	conversationID = strings.TrimSpace(conversationID)
	toolName = strings.TrimSpace(toolName)
	fingerprint = strings.TrimSpace(fingerprint)
	if conversationID == "" || toolName == "" || fingerprint == "" || since.IsZero() {
		return nil, nil
	}
	item, err := scanToolExecution(db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at, finished_at
		 FROM tool_executions
		 WHERE conversation_id = ? AND tool_name = ? AND fingerprint = ?
		   AND status = 'completed' AND started_at >= ?
		 ORDER BY started_at DESC
		 LIMIT 1`,
		conversationID,
		toolName,
		fingerprint,
		since.UTC().Unix(),
	))
	if err == nil {
		return item, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at, finished_at
		 FROM tool_executions
		 WHERE conversation_id = ? AND tool_name = ?
		   AND status = 'completed' AND fingerprint = '' AND started_at >= ?
		 ORDER BY started_at DESC
		 LIMIT 100`,
		conversationID,
		toolName,
		since.UTC().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		candidate, scanErr := scanToolExecution(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if ToolExecutionFingerprint(candidate.Arguments) == fingerprint {
			return candidate, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

// ListRecentProbeExecutions 返回会话最近网络类工具的完整执行参数。
func (db *DB) ListRecentProbeExecutions(
	ctx context.Context,
	conversationID string,
	since time.Time,
	limit int,
) ([]ToolExecution, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" || since.IsZero() {
		return []ToolExecution{}, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments, fingerprint,
			status, result, error, started_at, finished_at
		 FROM tool_executions
		 WHERE conversation_id = ?
		   AND tool_name IN ('exec', 'execute-python-script')
		   AND started_at >= ?
		 ORDER BY started_at DESC
		 LIMIT ?`,
		conversationID,
		since.UTC().Unix(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ToolExecution, 0, limit)
	for rows.Next() {
		item, scanErr := scanToolExecution(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

// ListRecentFailedToolExecutions 返回指定会话最近执行失败的工具记录。
func (db *DB) ListRecentFailedToolExecutions(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]ToolExecution, error) {
	if limit <= 0 || limit > 50 {
		limit = 5
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, status, error, started_at
		 FROM tool_executions
		 WHERE conversation_id = ? AND status = 'failed'
		 ORDER BY started_at DESC
		 LIMIT ?`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ToolExecution, 0)
	for rows.Next() {
		var item ToolExecution
		var startedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.UserID,
			&item.ToolName,
			&item.Status,
			&item.Error,
			&startedAt,
		); err != nil {
			return nil, err
		}
		item.StartedAt = time.Unix(startedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

// HasCompletedToolExecutionSince 判断会话在指定时间之后是否存在成功完成的工具执行。
func (db *DB) HasCompletedToolExecutionSince(
	ctx context.Context,
	conversationID string,
	since time.Time,
) (bool, error) {
	var exists int
	err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS(
			SELECT 1 FROM tool_executions
			WHERE conversation_id = ? AND status = 'completed' AND started_at >= ?
		)`,
		conversationID,
		since.Unix(),
	).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists != 0, nil
}
