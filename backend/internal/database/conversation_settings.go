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

// GetConversationAssetRestriction 返回会话级资产限制设置，未配置时默认开启。
func (db *DB) GetConversationAssetRestriction(
	ctx context.Context,
	conversationID string,
) (bool, error) {
	var value int
	err := db.QueryRowContext(
		ctx,
		`SELECT asset_restriction_enabled
		 FROM conversation_agent_settings WHERE conversation_id = ?`,
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

// SetConversationAssetRestriction 持久化会话级资产限制设置。
func (db *DB) SetConversationAssetRestriction(
	ctx context.Context,
	conversationID string,
	enabled bool,
) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversation_agent_settings (
			conversation_id, auto_continue, asset_restriction_enabled, updated_at
		) VALUES (?, 1, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			asset_restriction_enabled = excluded.asset_restriction_enabled,
			updated_at = excluded.updated_at`,
		conversationID,
		boolToInt(enabled),
		time.Now().UTC().Unix(),
	)
	return err
}
