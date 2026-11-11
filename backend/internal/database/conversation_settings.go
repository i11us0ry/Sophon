package database

import (
	"context"
	"database/sql"
	"time"
)

// GetConversationAutoContinue 返回会话级自动继续设置，未配置时默认开启。
func (db *DB) GetConversationAutoContinue(
	ctx context.Context,
	conversationID string,
) (bool, error) {
	var value int
	err := db.QueryRowContext(
		ctx,
		`SELECT auto_continue FROM conversation_agent_settings WHERE conversation_id = ?`,
		conversationID,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return value != 0, nil
}

// SetConversationAutoContinue 持久化会话级自动继续设置。
func (db *DB) SetConversationAutoContinue(
	ctx context.Context,
	conversationID string,
	enabled bool,
) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversation_agent_settings (
			conversation_id, auto_continue, updated_at
		) VALUES (?, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			auto_continue = excluded.auto_continue,
			updated_at = excluded.updated_at`,
		conversationID,
		boolToInt(enabled),
		time.Now().UTC().Unix(),
	)
	return err
}
