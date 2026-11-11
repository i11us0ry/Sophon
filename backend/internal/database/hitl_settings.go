package database

import (
	"context"
	"database/sql"
	"time"
)

// GetConversationHITLOverride 返回会话级人工审批覆盖；nil 表示跟随全局设置。
func (db *DB) GetConversationHITLOverride(
	ctx context.Context,
	conversationID string,
) (*bool, error) {
	var enabled int
	err := db.QueryRowContext(
		ctx,
		`SELECT enabled FROM conversation_hitl_settings WHERE conversation_id = ?`,
		conversationID,
	).Scan(&enabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	value := enabled != 0
	return &value, nil
}

func (db *DB) SetConversationHITLOverride(
	ctx context.Context,
	conversationID string,
	enabled bool,
) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversation_hitl_settings (conversation_id, enabled, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(conversation_id) DO UPDATE SET
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		conversationID,
		boolToInt(enabled),
		time.Now().UTC().Unix(),
	)
	return err
}
