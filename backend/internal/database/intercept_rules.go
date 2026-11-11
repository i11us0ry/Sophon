package database

import (
	"context"
	"time"
)

type InterceptRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	MatchTarget string    `json:"matchTarget"`
	MatchType   string    `json:"matchType"`
	Pattern     string    `json:"pattern"`
	Action      string    `json:"action"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (db *DB) ListInterceptRules(ctx context.Context) ([]InterceptRule, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, name, enabled, priority, match_target, match_type,
			pattern, action, message, created_at, updated_at
		 FROM intercept_rules
		 ORDER BY priority DESC, created_at ASC, id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]InterceptRule, 0)
	for rows.Next() {
		item, err := scanInterceptRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetInterceptRule(ctx context.Context, id string) (*InterceptRule, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, enabled, priority, match_target, match_type,
			pattern, action, message, created_at, updated_at
		 FROM intercept_rules WHERE id = ?`,
		id,
	)
	item, err := scanInterceptRule(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) CreateInterceptRule(ctx context.Context, item InterceptRule) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO intercept_rules (
			id, name, enabled, priority, match_target, match_type,
			pattern, action, message, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.Name,
		boolToInt(item.Enabled),
		item.Priority,
		item.MatchTarget,
		item.MatchType,
		item.Pattern,
		item.Action,
		item.Message,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpdateInterceptRule(ctx context.Context, item InterceptRule) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE intercept_rules
		 SET name = ?, enabled = ?, priority = ?, match_target = ?,
			match_type = ?, pattern = ?, action = ?, message = ?, updated_at = ?
		 WHERE id = ?`,
		item.Name,
		boolToInt(item.Enabled),
		item.Priority,
		item.MatchTarget,
		item.MatchType,
		item.Pattern,
		item.Action,
		item.Message,
		item.UpdatedAt.Unix(),
		item.ID,
	)
	return requireAffected(result, err)
}

func (db *DB) DeleteInterceptRule(ctx context.Context, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM intercept_rules WHERE id = ?`, id)
	return requireAffected(result, err)
}

func (db *DB) SetInterceptRuleEnabled(ctx context.Context, id string, enabled bool) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE intercept_rules SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled),
		time.Now().UTC().Unix(),
		id,
	)
	return requireAffected(result, err)
}

func scanInterceptRule(scanner rowScanner) (InterceptRule, error) {
	var item InterceptRule
	var enabled int
	var createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.Name,
		&enabled,
		&item.Priority,
		&item.MatchTarget,
		&item.MatchType,
		&item.Pattern,
		&item.Action,
		&item.Message,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.Enabled = enabled != 0
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return item, nil
}
