package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	AgentTriggerPending    = "pending"
	AgentTriggerProcessing = "processing"
	AgentTriggerConsumed   = "consumed"

	AgentTriggerDone       = "done"
	AgentTriggerFinding    = "finding"
	AgentTriggerHint       = "hint"
	AgentTriggerGoal       = "goal"
	AgentTriggerGoalEdit   = "goal_edited"
	AgentTriggerGoalDelete = "goal_deleted"
	AgentTriggerCancelled  = "cancelled"
	AgentTriggerHeartbeat  = "heartbeat"
)

type AgentTrigger struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversationId"`
	ProjectID      string                 `json:"projectId"`
	Kind           string                 `json:"kind"`
	IntentID       string                 `json:"intentId"`
	Payload        map[string]interface{} `json:"payload"`
	DedupeKey      string                 `json:"dedupeKey"`
	Status         string                 `json:"status"`
	CreatedAt      time.Time              `json:"createdAt"`
	ConsumedAt     time.Time              `json:"consumedAt"`
}

func NormalizeAgentTriggerKind(value string) (string, bool) {
	switch kind := strings.ToLower(strings.TrimSpace(value)); kind {
	case AgentTriggerDone,
		AgentTriggerFinding,
		AgentTriggerHint,
		AgentTriggerGoal,
		AgentTriggerGoalEdit,
		AgentTriggerGoalDelete,
		AgentTriggerCancelled,
		AgentTriggerHeartbeat:
		return kind, true
	default:
		return "", false
	}
}

func (db *DB) EnqueueAgentTrigger(
	ctx context.Context,
	item AgentTrigger,
) (*AgentTrigger, error) {
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.IntentID = strings.TrimSpace(item.IntentID)
	item.DedupeKey = strings.TrimSpace(item.DedupeKey)
	kind, ok := NormalizeAgentTriggerKind(item.Kind)
	if !ok {
		return nil, fmt.Errorf("Trigger 类型不合法")
	}
	if item.ConversationID == "" {
		return nil, fmt.Errorf("Trigger 会话不能为空")
	}
	if item.ID == "" {
		item.ID = newID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	payload := item.Payload
	if payload == nil {
		payload = map[string]interface{}{}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("编码 Trigger 失败: %w", err)
	}
	result, err := db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO agent_triggers (
			id, conversation_id, project_id, kind, intent_id,
			payload_json, dedupe_key, status, created_at, consumed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		item.ID,
		item.ConversationID,
		item.ProjectID,
		kind,
		item.IntentID,
		string(encoded),
		item.DedupeKey,
		AgentTriggerPending,
		item.CreatedAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr == nil && affected == 0 {
		return nil, nil
	}
	item.Kind = kind
	item.Payload = payload
	item.Status = AgentTriggerPending
	return &item, nil
}

func (db *DB) DrainPendingAgentTriggers(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]AgentTrigger, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, fmt.Errorf("Trigger 会话不能为空")
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(
		ctx,
		`SELECT t.id, t.conversation_id, t.project_id, t.kind, t.intent_id,
			t.payload_json, t.dedupe_key, t.status, t.created_at, t.consumed_at
		 FROM agent_triggers t
		 JOIN conversations c ON c.id = t.conversation_id
		 JOIN projects p ON p.id = c.project_id
			WHERE t.conversation_id = ? AND t.status IN (?, ?)
			  AND p.status = 'active'
		 ORDER BY t.created_at ASC, t.rowid ASC
		 LIMIT ?`,
		conversationID,
		AgentTriggerPending,
		AgentTriggerProcessing,
		limit,
	)
	if err != nil {
		return nil, err
	}
	items := make([]AgentTrigger, 0)
	for rows.Next() {
		var item AgentTrigger
		var payloadJSON string
		var createdAt, consumedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.ProjectID,
			&item.Kind,
			&item.IntentID,
			&payloadJSON,
			&item.DedupeKey,
			&item.Status,
			&createdAt,
			&consumedAt,
		); err != nil {
			_ = rows.Close()
			return nil, err
		}
		item.Payload = map[string]interface{}{}
		_ = json.Unmarshal([]byte(payloadJSON), &item.Payload)
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		if consumedAt > 0 {
			item.ConsumedAt = time.Unix(consumedAt, 0).UTC()
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return items, nil
	}
	for index, item := range items {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE agent_triggers
			 SET status = ?, consumed_at = ?
			 WHERE id = ? AND status IN (?, ?)`,
			AgentTriggerProcessing,
			0,
			item.ID,
			AgentTriggerPending,
			AgentTriggerProcessing,
		); err != nil {
			return nil, err
		}
		items[index].Status = AgentTriggerProcessing
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func (db *DB) CompleteAgentTriggers(
	ctx context.Context,
	ids []string,
) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC().Unix()
	for _, id := range ids {
		if _, err := db.ExecContext(
			ctx,
			`UPDATE agent_triggers
			 SET status = ?, consumed_at = ?
			 WHERE id = ? AND status = ?`,
			AgentTriggerConsumed,
			now,
			strings.TrimSpace(id),
			AgentTriggerProcessing,
		); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) ReleaseAgentTriggers(
	ctx context.Context,
	ids []string,
) error {
	if len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		if _, err := db.ExecContext(
			ctx,
			`UPDATE agent_triggers
			 SET status = ?
			 WHERE id = ? AND status = ?`,
			AgentTriggerPending,
			strings.TrimSpace(id),
			AgentTriggerProcessing,
		); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) RecoverProcessingAgentTriggers(ctx context.Context) (int64, error) {
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_triggers SET status = ? WHERE status = ?`,
		AgentTriggerPending,
		AgentTriggerProcessing,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) CountPendingAgentTriggers(
	ctx context.Context,
	conversationID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM agent_triggers
		 WHERE conversation_id = ? AND status IN (?, ?)`,
		strings.TrimSpace(conversationID),
		AgentTriggerPending,
		AgentTriggerProcessing,
	).Scan(&count)
	return count, err
}
