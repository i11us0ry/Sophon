package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	BackgroundUpdatePending    = "pending"
	BackgroundUpdateProcessing = "processing"
	BackgroundUpdateDelivered  = "delivered"
	BackgroundUpdateSuppressed = "suppressed"
)

type BackgroundUpdateEvent struct {
	ID             string
	ConversationID string
	ProjectID      string
	OwnerUserID    string
	Kind           string
	Priority       int
	DedupeKey      string
	PayloadJSON    string
	Status         string
	Attempts       int
	NotBefore      time.Time
	CreatedAt      time.Time
	ProcessedAt    time.Time
}

func (db *DB) EnqueueBackgroundUpdate(
	ctx context.Context,
	item BackgroundUpdateEvent,
) error {
	item.ID = strings.TrimSpace(item.ID)
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.Kind = strings.TrimSpace(item.Kind)
	item.DedupeKey = strings.TrimSpace(item.DedupeKey)
	if item.ID == "" || item.ConversationID == "" || item.OwnerUserID == "" || item.Kind == "" {
		return fmt.Errorf("后台更新事件缺少 id、会话、用户或类型")
	}
	if item.Priority <= 0 {
		item.Priority = 50
	}
	if strings.TrimSpace(item.PayloadJSON) == "" {
		item.PayloadJSON = "{}"
	}
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if item.NotBefore.IsZero() {
		item.NotBefore = item.CreatedAt
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO background_update_events (
			id, conversation_id, project_id, owner_user_id, kind, priority,
			dedupe_key, payload_json, status, attempts, not_before, created_at, processed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)
		ON CONFLICT(conversation_id, dedupe_key) WHERE dedupe_key <> '' DO NOTHING`,
		item.ID,
		item.ConversationID,
		item.ProjectID,
		item.OwnerUserID,
		item.Kind,
		item.Priority,
		item.DedupeKey,
		item.PayloadJSON,
		BackgroundUpdatePending,
		item.NotBefore.Unix(),
		item.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("写入后台更新事件失败: %w", err)
	}
	return nil
}

func (db *DB) ListPendingBackgroundUpdateConversations(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]string, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT conversation_id
		 FROM background_update_events
		 WHERE status = ? AND not_before <= ?
		 GROUP BY conversation_id
		 ORDER BY MIN(created_at) ASC
		 LIMIT ?`,
		BackgroundUpdatePending,
		now.UTC().Unix(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0, limit)
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			return nil, err
		}
		if conversationID = strings.TrimSpace(conversationID); conversationID != "" {
			items = append(items, conversationID)
		}
	}
	return items, rows.Err()
}

func (db *DB) ClaimBackgroundUpdatesForConversation(
	ctx context.Context,
	conversationID string,
	now time.Time,
	limit int,
) ([]BackgroundUpdateEvent, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return []BackgroundUpdateEvent{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`UPDATE background_update_events
		 SET status = ?, attempts = attempts + 1
		 WHERE conversation_id = ?
		   AND status = ?
		   AND not_before <= ?
		   AND id IN (
		     SELECT id FROM background_update_events
		     WHERE conversation_id = ?
		       AND status = ?
		       AND not_before <= ?
		     ORDER BY priority DESC, created_at ASC
		     LIMIT ?
		   )
		 RETURNING id, conversation_id, project_id, owner_user_id, kind,
		           priority, dedupe_key, payload_json, status, attempts,
		           not_before, created_at, processed_at`,
		BackgroundUpdateProcessing,
		conversationID,
		BackgroundUpdatePending,
		now.UTC().Unix(),
		conversationID,
		BackgroundUpdatePending,
		now.UTC().Unix(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]BackgroundUpdateEvent, 0, limit)
	for rows.Next() {
		var item BackgroundUpdateEvent
		var notBefore, createdAt, processedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Kind,
			&item.Priority,
			&item.DedupeKey,
			&item.PayloadJSON,
			&item.Status,
			&item.Attempts,
			&notBefore,
			&createdAt,
			&processedAt,
		); err != nil {
			return nil, err
		}
		item.NotBefore = time.Unix(notBefore, 0).UTC()
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		if processedAt > 0 {
			item.ProcessedAt = time.Unix(processedAt, 0).UTC()
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ReleaseBackgroundUpdates(
	ctx context.Context,
	ids []string,
	notBefore time.Time,
) error {
	ids = nonEmptyStrings(ids)
	if len(ids) == 0 {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE background_update_events
		 SET status = ?, not_before = ?
		 WHERE status = ? AND id IN (`+placeholders(len(ids))+`)`,
		buildIDArgs(
			[]interface{}{BackgroundUpdatePending, notBefore.UTC().Unix(), BackgroundUpdateProcessing},
			ids,
		)...,
	)
	return err
}

func (db *DB) CompleteBackgroundUpdates(
	ctx context.Context,
	ids []string,
	status string,
) error {
	ids = nonEmptyStrings(ids)
	if len(ids) == 0 {
		return nil
	}
	status = strings.TrimSpace(status)
	if status != BackgroundUpdateDelivered && status != BackgroundUpdateSuppressed {
		return fmt.Errorf("后台更新完成状态不合法")
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE background_update_events
		 SET status = ?, processed_at = ?
		 WHERE status = ? AND id IN (`+placeholders(len(ids))+`)`,
		buildIDArgs(
			[]interface{}{status, time.Now().UTC().Unix(), BackgroundUpdateProcessing},
			ids,
		)...,
	)
	return err
}

func (db *DB) RecoverProcessingBackgroundUpdates(ctx context.Context) (int64, error) {
	result, err := db.ExecContext(
		ctx,
		`UPDATE background_update_events
		 SET status = ?, not_before = ?
		 WHERE status = ?`,
		BackgroundUpdatePending,
		time.Now().UTC().Unix(),
		BackgroundUpdateProcessing,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) CountPendingBackgroundUpdates(
	ctx context.Context,
	conversationID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM background_update_events
		 WHERE conversation_id = ? AND status = ?`,
		strings.TrimSpace(conversationID),
		BackgroundUpdatePending,
	).Scan(&count)
	return count, err
}
