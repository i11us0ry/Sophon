package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type TokenUsage struct {
	ID               string
	ConversationID   string
	UserID           string
	MessageID        string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	Estimated        bool
	Kind             string
	Model            string
	CreatedAt        time.Time
}

type DashboardSummary struct {
	Conversations         int
	Vulnerabilities       int
	ToolCalls             int
	AssetTotal            int
	AssetCriticality      map[string]int
	AssetStatus           map[string]int
	PromptTokens          int
	CompletionTokens      int
	TotalTokens           int
	EstimatedTokens       bool
	VulnerabilityStatus   map[string]int
	VulnerabilitySeverity map[string]int
}

func (db *DB) AddTokenUsage(ctx context.Context, item TokenUsage) error {
	conversationID := strings.TrimSpace(item.ConversationID)
	userID := strings.TrimSpace(item.UserID)
	if conversationID == "" || userID == "" {
		return fmt.Errorf("token usage requires conversation and user")
	}
	var projectID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id FROM conversations
		 WHERE id = ? AND owner_user_id = ?`,
		conversationID,
		userID,
	).Scan(&projectID); err != nil {
		return fmt.Errorf("token usage conversation not found or owner mismatch: %w", err)
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO token_usage (
			id, conversation_id, project_id, user_id, message_id,
			prompt_tokens, completion_tokens, total_tokens, estimated,
			kind, model, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		conversationID,
		projectID,
		userID,
		item.MessageID,
		item.PromptTokens,
		item.CompletionTokens,
		item.TotalTokens,
		boolToInt(item.Estimated),
		normalizeTokenUsageKind(item.Kind),
		item.Model,
		item.CreatedAt.Unix(),
	)
	return err
}

// TokenUsageForMessage 返回同一助手消息（即同一轮对话）的累计 token 用量。
func (db *DB) TokenUsageForMessage(ctx context.Context, messageID string) (int, error) {
	if db == nil || strings.TrimSpace(messageID) == "" {
		return 0, nil
	}
	var total int
	err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(SUM(total_tokens), 0) FROM token_usage
		 WHERE message_id = ? AND kind IN ('chat', 'subagent')`,
		strings.TrimSpace(messageID),
	).Scan(&total)
	return total, err
}

func normalizeTokenUsageKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "chat"
	}
	return kind
}

func (db *DB) DashboardSummary(ctx context.Context, userID string) (*DashboardSummary, error) {
	summary := &DashboardSummary{}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM conversations WHERE owner_user_id = ?`,
		userID,
	).Scan(&summary.Conversations); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE owner_user_id = ?`,
		userID,
	).Scan(&summary.Vulnerabilities); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets WHERE owner_user_id = ?`,
		userID,
	).Scan(&summary.AssetTotal); err != nil {
		return nil, err
	}
	summary.AssetCriticality = map[string]int{}
	if err := db.scanCounts(
		ctx,
		`SELECT criticality, COUNT(*) FROM assets
		 WHERE owner_user_id = ? GROUP BY criticality`,
		userID,
		summary.AssetCriticality,
	); err != nil {
		return nil, err
	}
	summary.AssetStatus = map[string]int{}
	if err := db.scanCounts(
		ctx,
		`SELECT status, COUNT(*) FROM assets
		 WHERE owner_user_id = ? GROUP BY status`,
		userID,
		summary.AssetStatus,
	); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tool_executions WHERE user_id = ?`,
		userID,
	).Scan(&summary.ToolCalls); err != nil {
		return nil, err
	}
	summary.VulnerabilityStatus = map[string]int{}
	if err := db.scanCounts(
		ctx,
		`SELECT status, COUNT(*) FROM vulnerabilities
		 WHERE owner_user_id = ? GROUP BY status`,
		userID,
		summary.VulnerabilityStatus,
	); err != nil {
		return nil, err
	}
	summary.VulnerabilitySeverity = map[string]int{}
	if err := db.scanCounts(
		ctx,
		`SELECT severity, COUNT(*) FROM vulnerabilities
		 WHERE owner_user_id = ? GROUP BY severity`,
		userID,
		summary.VulnerabilitySeverity,
	); err != nil {
		return nil, err
	}
	var estimated int
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COALESCE(SUM(prompt_tokens), 0),
			COALESCE(SUM(completion_tokens), 0),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(MAX(estimated), 0)
		 FROM token_usage WHERE user_id = ?`,
		userID,
	).Scan(
		&summary.PromptTokens,
		&summary.CompletionTokens,
		&summary.TotalTokens,
		&estimated,
	); err != nil {
		return nil, err
	}
	summary.EstimatedTokens = estimated != 0
	return summary, nil
}

func (db *DB) scanCounts(
	ctx context.Context,
	query string,
	userID string,
	target map[string]int,
) error {
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		target[key] = count
	}
	return rows.Err()
}
