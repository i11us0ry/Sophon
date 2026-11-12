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
	CacheReadTokens  int
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
	CacheReadTokens       int
	CompletionTokens      int
	TotalTokens           int
	EstimatedTokens       bool
	VulnerabilityStatus   map[string]int
	VulnerabilitySeverity map[string]int
}

type DashboardTokenDay struct {
	Date            string `json:"date"`
	InputTokens     int    `json:"inputTokens"`
	CacheReadTokens int    `json:"cacheReadTokens"`
	OutputTokens    int    `json:"outputTokens"`
}

type DashboardTokenModel struct {
	Model           string `json:"model"`
	Calls           int    `json:"calls"`
	Tasks           int    `json:"tasks"`
	InputTokens     int    `json:"inputTokens"`
	CacheReadTokens int    `json:"cacheReadTokens"`
	OutputTokens    int    `json:"outputTokens"`
}

type DashboardTokenStats struct {
	InputTokens     int                   `json:"inputTokens"`
	CacheReadTokens int                   `json:"cacheReadTokens"`
	OutputTokens    int                   `json:"outputTokens"`
	TotalTokens     int                   `json:"totalTokens"`
	TaskCount       int                   `json:"taskCount"`
	Calls           int                   `json:"calls"`
	Estimated       bool                  `json:"estimated"`
	Days            int                   `json:"days"`
	Models          []DashboardTokenModel `json:"models"`
	Daily           []DashboardTokenDay   `json:"daily"`
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
			prompt_tokens, cache_read_tokens, completion_tokens, total_tokens, estimated,
			kind, model, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		conversationID,
		projectID,
		userID,
		item.MessageID,
		item.PromptTokens,
		item.CacheReadTokens,
		item.CompletionTokens,
		item.TotalTokens,
		boolToInt(item.Estimated),
		normalizeTokenUsageKind(item.Kind),
		item.Model,
		item.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) DashboardTokenStats(
	ctx context.Context,
	userID string,
	days int,
	model string,
	legacy bool,
) (*DashboardTokenStats, error) {
	if days != 7 && days != 30 && days != 90 && days != 180 && days != 365 {
		days = 30
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Unix()
	baseClauses := []string{
		"user_id = ?",
		"created_at >= ?",
		"kind IN ('chat', 'subagent', 'summary')",
	}
	baseArgs := []interface{}{userID, cutoff}
	clauses := append([]string(nil), baseClauses...)
	args := append([]interface{}(nil), baseArgs...)
	model = strings.TrimSpace(model)
	if model == "__default__" {
		clauses = append(clauses, "TRIM(model) = ''")
	} else if model != "" {
		clauses = append(clauses, "model = ?")
		args = append(args, model)
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	baseWhere := " WHERE " + strings.Join(baseClauses, " AND ")
	stats := &DashboardTokenStats{Days: days}
	var estimated int
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COALESCE(SUM(prompt_tokens), 0),
			COALESCE(SUM(cache_read_tokens), 0),
			COALESCE(SUM(completion_tokens), 0),
			COUNT(DISTINCT conversation_id),
			COUNT(*),
			COALESCE(MAX(estimated), 0)
		 FROM token_usage`+where,
		args...,
	).Scan(
		&stats.InputTokens,
		&stats.CacheReadTokens,
		&stats.OutputTokens,
		&stats.TaskCount,
		&stats.Calls,
		&estimated,
	); err != nil {
		return nil, err
	}
	if legacy {
		stats.CacheReadTokens = 0
	}
	stats.InputTokens = maxInt(stats.InputTokens, 0)
	stats.CacheReadTokens = minInt(maxInt(stats.CacheReadTokens, 0), stats.InputTokens)
	stats.OutputTokens = maxInt(stats.OutputTokens, 0)
	stats.TotalTokens = stats.InputTokens + stats.OutputTokens
	stats.Estimated = estimated != 0
	stats.Models = make([]DashboardTokenModel, 0)
	modelRows, err := db.QueryContext(
		ctx,
		`SELECT
			TRIM(model),
			COUNT(*),
			COUNT(DISTINCT conversation_id),
			COALESCE(SUM(prompt_tokens), 0),
			COALESCE(SUM(cache_read_tokens), 0),
			COALESCE(SUM(completion_tokens), 0)
		 FROM token_usage`+baseWhere+`
		 GROUP BY TRIM(model)
		 ORDER BY SUM(prompt_tokens + completion_tokens) DESC, model ASC
		 LIMIT 20`,
		baseArgs...,
	)
	if err != nil {
		return nil, err
	}
	for modelRows.Next() {
		var item DashboardTokenModel
		if err := modelRows.Scan(
			&item.Model,
			&item.Calls,
			&item.Tasks,
			&item.InputTokens,
			&item.CacheReadTokens,
			&item.OutputTokens,
		); err != nil {
			_ = modelRows.Close()
			return nil, err
		}
		if legacy {
			item.CacheReadTokens = 0
		}
		item.CacheReadTokens = minInt(maxInt(item.CacheReadTokens, 0), maxInt(item.InputTokens, 0))
		stats.Models = append(stats.Models, item)
	}
	if err := modelRows.Close(); err != nil {
		return nil, err
	}
	stats.Daily = make([]DashboardTokenDay, 0)
	rows, err := db.QueryContext(
		ctx,
		`SELECT
			strftime('%Y-%m-%d', created_at, 'unixepoch') AS day,
			COALESCE(SUM(prompt_tokens), 0),
			COALESCE(SUM(cache_read_tokens), 0),
			COALESCE(SUM(completion_tokens), 0)
		 FROM token_usage`+where+`
		 GROUP BY day
		 ORDER BY day ASC`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item DashboardTokenDay
		if err := rows.Scan(
			&item.Date,
			&item.InputTokens,
			&item.CacheReadTokens,
			&item.OutputTokens,
		); err != nil {
			return nil, err
		}
		if legacy {
			item.CacheReadTokens = 0
		}
		item.CacheReadTokens = minInt(maxInt(item.CacheReadTokens, 0), maxInt(item.InputTokens, 0))
		stats.Daily = append(stats.Daily, item)
	}
	return stats, rows.Err()
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
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
			COALESCE(SUM(cache_read_tokens), 0),
			COALESCE(SUM(completion_tokens), 0),
			COALESCE(SUM(total_tokens), 0),
			COALESCE(MAX(estimated), 0)
		 FROM token_usage WHERE user_id = ?`,
		userID,
	).Scan(
		&summary.PromptTokens,
		&summary.CacheReadTokens,
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
