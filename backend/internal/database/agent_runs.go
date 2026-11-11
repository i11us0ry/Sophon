package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const (
	AgentRunStatusRunning     = "running"
	AgentRunStatusCompleted   = "completed"
	AgentRunStatusFailed      = "failed"
	AgentRunStatusInterrupted = "interrupted"
	AgentRunStatusCancelled   = "cancelled"
	AgentRunModeFast          = "fast"
	AgentRunModeDeep          = "deep"
)

type AgentRun struct {
	ID                 string    `json:"id"`
	ConversationID     string    `json:"conversationId"`
	AssistantMessageID string    `json:"assistantMessageId"`
	ResumeOf           string    `json:"resumeOf"`
	AgentMode          string    `json:"agentMode"`
	Status             string    `json:"status"`
	SegmentCount       int       `json:"segmentCount"`
	ProgressJSON       string    `json:"progressJson"`
	InterruptionReason string    `json:"interruptionReason"`
	Error              string    `json:"error"`
	StartedAt          time.Time `json:"startedAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
	FinishedAt         time.Time `json:"finishedAt,omitempty"`
}

func (db *DB) CreateAgentRun(ctx context.Context, run AgentRun) error {
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	if run.UpdatedAt.IsZero() {
		run.UpdatedAt = run.StartedAt
	}
	if strings.TrimSpace(run.Status) == "" {
		run.Status = AgentRunStatusRunning
	}
	if strings.TrimSpace(run.AgentMode) == "" {
		run.AgentMode = AgentRunModeDeep
	}
	if strings.TrimSpace(run.ProgressJSON) == "" {
		run.ProgressJSON = "{}"
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO agent_runs (
			id, conversation_id, assistant_message_id, resume_of, agent_mode, status,
			segment_count, progress_json, interruption_reason, error,
			started_at, updated_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?, NULL)`,
		run.ID,
		run.ConversationID,
		run.AssistantMessageID,
		run.ResumeOf,
		run.AgentMode,
		run.Status,
		run.SegmentCount,
		run.ProgressJSON,
		run.StartedAt.Unix(),
		run.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpdateAgentRunProgress(
	ctx context.Context,
	id string,
	segmentCount int,
	progressJSON string,
) error {
	if segmentCount < 0 {
		segmentCount = 0
	}
	if strings.TrimSpace(progressJSON) == "" {
		progressJSON = "{}"
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE agent_runs
		 SET segment_count = ?, progress_json = ?, updated_at = ?
		 WHERE id = ? AND status = ?`,
		segmentCount,
		progressJSON,
		time.Now().UTC().Unix(),
		id,
		AgentRunStatusRunning,
	)
	return err
}

func (db *DB) FinishAgentRun(
	ctx context.Context,
	id string,
	status string,
	errText string,
	interruptionReason string,
) error {
	status = strings.TrimSpace(status)
	switch status {
	case AgentRunStatusCompleted, AgentRunStatusFailed,
		AgentRunStatusInterrupted, AgentRunStatusCancelled:
	default:
		status = AgentRunStatusFailed
	}
	now := time.Now().UTC()
	_, err := db.ExecContext(
		ctx,
		`UPDATE agent_runs
		 SET status = ?, error = ?, interruption_reason = ?, updated_at = ?, finished_at = ?
		 WHERE id = ? AND status = ?`,
		status,
		errText,
		interruptionReason,
		now.Unix(),
		now.Unix(),
		id,
		AgentRunStatusRunning,
	)
	return err
}

func (db *DB) GetLatestAgentRun(
	ctx context.Context,
	conversationID string,
) (*AgentRun, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, assistant_message_id, resume_of, agent_mode, status,
			segment_count, progress_json, interruption_reason, error,
			started_at, updated_at, COALESCE(finished_at, 0)
		 FROM agent_runs
		 WHERE conversation_id = ?
		 ORDER BY started_at DESC, rowid DESC
		 LIMIT 1`,
		conversationID,
	)
	item, err := scanAgentRun(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return item, nil
}

func (db *DB) GetResumableAgentRun(
	ctx context.Context,
	conversationID string,
) (*AgentRun, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, assistant_message_id, resume_of, agent_mode, status,
			segment_count, progress_json, interruption_reason, error,
			started_at, updated_at, COALESCE(finished_at, 0)
		 FROM agent_runs
		 WHERE conversation_id = ? AND status = ?
		   AND id = (
		   	SELECT latest.id FROM agent_runs latest
		   	WHERE latest.conversation_id = agent_runs.conversation_id
		   	ORDER BY latest.started_at DESC, latest.rowid DESC
		   	LIMIT 1
		   )
		 ORDER BY started_at DESC, rowid DESC
		 LIMIT 1`,
		conversationID,
		AgentRunStatusInterrupted,
	)
	item, err := scanAgentRun(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return item, nil
}

func (db *DB) MarkAssistantMessageInterrupted(
	ctx context.Context,
	messageID string,
	notice string,
) error {
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE messages
		 SET content = CASE
		 	WHEN TRIM(content) = '' THEN ?
		 	ELSE content || char(10) || char(10) || '---' || char(10) || ?
		 END
		 WHERE id = ?`,
		notice,
		notice,
		messageID,
	)
	return err
}

// MarkStaleAgentRunsInterrupted 在服务启动时标记上次进程遗留的 running 任务。
func (db *DB) MarkStaleAgentRunsInterrupted(
	ctx context.Context,
	reason string,
) ([]AgentRun, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, assistant_message_id, resume_of, agent_mode, status,
			segment_count, progress_json, interruption_reason, error,
			started_at, updated_at, COALESCE(finished_at, 0)
		 FROM agent_runs
		 WHERE status = ?
		 ORDER BY started_at ASC`,
		AgentRunStatusRunning,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentRun, 0)
	for rows.Next() {
		item, scanErr := scanAgentRunRows(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	if len(items) == 0 {
		return items, nil
	}
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, item := range items {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE agent_runs
			 SET status = ?, interruption_reason = ?, updated_at = ?, finished_at = ?
			 WHERE id = ? AND status = ?`,
			AgentRunStatusInterrupted,
			reason,
			now.Unix(),
			now.Unix(),
			item.ID,
			AgentRunStatusRunning,
		); err != nil {
			return nil, err
		}
		item.Status = AgentRunStatusInterrupted
		item.InterruptionReason = reason
		item.UpdatedAt = now
		item.FinishedAt = now
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

type agentRunScanner interface {
	Scan(dest ...interface{}) error
}

func scanAgentRun(row agentRunScanner) (*AgentRun, error) {
	var item AgentRun
	var startedAt, updatedAt, finishedAt int64
	if err := row.Scan(
		&item.ID,
		&item.ConversationID,
		&item.AssistantMessageID,
		&item.ResumeOf,
		&item.AgentMode,
		&item.Status,
		&item.SegmentCount,
		&item.ProgressJSON,
		&item.InterruptionReason,
		&item.Error,
		&startedAt,
		&updatedAt,
		&finishedAt,
	); err != nil {
		return nil, err
	}
	item.StartedAt = time.Unix(startedAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	if finishedAt > 0 {
		item.FinishedAt = time.Unix(finishedAt, 0)
	}
	return &item, nil
}

func scanAgentRunRows(rows *sql.Rows) (AgentRun, error) {
	item, err := scanAgentRun(rows)
	if err != nil {
		return AgentRun{}, err
	}
	return *item, nil
}
