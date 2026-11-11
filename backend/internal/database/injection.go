package database

import (
	"context"
	"time"
)

// InjectionEvent 记录一次疑似提示注入事件（事实打污点或摘要命中特征）。
type InjectionEvent struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId"`
	ProjectID      string    `json:"projectId"`
	SourceType     string    `json:"sourceType"`
	SourceID       string    `json:"sourceId"`
	Patterns       string    `json:"patterns"`
	Action         string    `json:"action"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (db *DB) AddInjectionEvent(ctx context.Context, item InjectionEvent) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO injection_events (
			id, conversation_id, project_id, source_type, source_id, patterns, action, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ConversationID,
		item.ProjectID,
		item.SourceType,
		item.SourceID,
		item.Patterns,
		item.Action,
		item.CreatedAt.Unix(),
	)
	return err
}

// CountInjectionEvents 统计注入事件；all=true 时返回全局数据（仅管理员调用）。
func (db *DB) CountInjectionEvents(ctx context.Context, userID string, all bool) (int, error) {
	query := `SELECT COUNT(*) FROM injection_events e`
	args := []interface{}{}
	if !all {
		query += ` JOIN conversations conv ON conv.id = e.conversation_id
		 WHERE conv.owner_user_id = ?`
		args = append(args, userID)
	}
	var count int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (db *DB) ListInjectionEvents(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]InjectionEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, project_id, source_type, source_id, patterns, action, created_at
		 FROM injection_events
		 WHERE (? = '' OR conversation_id = ?)
		 ORDER BY created_at DESC
		 LIMIT ?`,
		conversationID,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]InjectionEvent, 0)
	for rows.Next() {
		var item InjectionEvent
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.ProjectID,
			&item.SourceType,
			&item.SourceID,
			&item.Patterns,
			&item.Action,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}
