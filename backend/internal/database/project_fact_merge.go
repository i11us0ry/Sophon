package database

import (
	"context"
	"database/sql"
	"strings"
)

// GetProjectFactByFingerprint 查找同一资产、同一规范化主题的活跃事实。
func (db *DB) GetProjectFactByFingerprint(
	ctx context.Context,
	projectID string,
	assetID string,
	fingerprint string,
) (*ProjectFact, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, nil
	}
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND asset_id = ? AND fact_fingerprint = ?
		   AND valid_to = 0 AND superseded_by = ''
		 ORDER BY updated_at DESC
		 LIMIT 1`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(assetID),
		fingerprint,
	)
	item, err := scanProjectFact(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (db *DB) SetProjectFactFingerprint(
	ctx context.Context,
	factID string,
	fingerprint string,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET fact_fingerprint = ?
		 WHERE id = ? AND (fact_fingerprint = '' OR fact_fingerprint = ?)`,
		strings.TrimSpace(fingerprint),
		strings.TrimSpace(factID),
		strings.TrimSpace(fingerprint),
	)
	return err
}
