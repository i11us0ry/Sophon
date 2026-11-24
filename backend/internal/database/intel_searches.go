package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type IntelSearchRecord struct {
	ID                 string
	OwnerUserID        string
	ProjectID          string
	Provider           string
	Query              string
	Page               int
	PageSize           int
	StartTime          string
	ResultCount        int
	ResultsJSON        string
	ProviderErrorsJSON string
	CreatedAt          time.Time
}

func (db *DB) CreateIntelSearch(ctx context.Context, item IntelSearchRecord) error {
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO intel_searches (
			id, owner_user_id, project_id, provider, query, page, page_size,
			start_time, result_count, results_json, provider_errors_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.OwnerUserID,
		strings.TrimSpace(item.ProjectID),
		strings.ToLower(strings.TrimSpace(item.Provider)),
		strings.TrimSpace(item.Query),
		item.Page,
		item.PageSize,
		strings.TrimSpace(item.StartTime),
		item.ResultCount,
		item.ResultsJSON,
		item.ProviderErrorsJSON,
		item.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) ListIntelSearches(
	ctx context.Context,
	ownerUserID string,
	projectID string,
	limit int,
	offset int,
) ([]IntelSearchRecord, int, error) {
	limit, offset = normalizeProjectPage(limit, offset)
	if limit > 100 {
		limit = 100
	}
	clauses := []string{"owner_user_id = ?"}
	args := []interface{}{ownerUserID}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		clauses = append(clauses, "project_id = ?")
		args = append(args, projectID)
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM intel_searches`+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]interface{}(nil), args...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, provider, query, page, page_size, start_time,
			result_count, created_at
		 FROM intel_searches`+where+`
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]IntelSearchRecord, 0)
	for rows.Next() {
		var item IntelSearchRecord
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.Provider,
			&item.Query,
			&item.Page,
			&item.PageSize,
			&item.StartTime,
			&item.ResultCount,
			&createdAt,
		); err != nil {
			return nil, 0, err
		}
		item.OwnerUserID = ownerUserID
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (db *DB) GetIntelSearch(
	ctx context.Context,
	id string,
	ownerUserID string,
) (*IntelSearchRecord, error) {
	var item IntelSearchRecord
	var createdAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, owner_user_id, project_id, provider, query, page, page_size,
			start_time, result_count, results_json, provider_errors_json, created_at
		 FROM intel_searches
		 WHERE id = ? AND owner_user_id = ?`,
		strings.TrimSpace(id),
		ownerUserID,
	).Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.Provider,
		&item.Query,
		&item.Page,
		&item.PageSize,
		&item.StartTime,
		&item.ResultCount,
		&item.ResultsJSON,
		&item.ProviderErrorsJSON,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	return &item, nil
}

func (db *DB) DeleteIntelSearch(ctx context.Context, id string, ownerUserID string) error {
	result, err := db.ExecContext(
		ctx,
		`DELETE FROM intel_searches WHERE id = ? AND owner_user_id = ?`,
		strings.TrimSpace(id),
		ownerUserID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
