package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"
)

type vulnerabilityAssetBackfill struct {
	ID       string
	Title    string
	Project  string
	Owner    string
	Target   string
	Severity string
}

type factAssetRelation struct {
	ID       string
	Project  string
	Owner    string
	Key      string
	Relation string
}

// backfillProjectAssets 为历史项目补建并关联可明确识别的资产。
func (db *DB) backfillProjectAssets(ctx context.Context) error {
	vulnerabilities, err := db.listVulnerabilitiesMissingAssets(ctx)
	if err != nil {
		return err
	}
	facts, err := db.listFactAssetRelations(ctx)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, item := range vulnerabilities {
		assetID, err := ensureProjectAsset(
			ctx,
			tx,
			item.Project,
			item.Owner,
			item.Target,
			assetRiskScoreForSeverity(item.Severity),
		)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE vulnerabilities SET asset_id = ? WHERE id = ? AND project_id = ?`,
			assetID,
			item.ID,
			item.Project,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_graph_nodes SET asset_id = ?, updated_at = ?
			 WHERE project_id = ? AND kind = 'finding' AND source_ref_id = ?`,
			assetID,
			time.Now().UTC().Unix(),
			item.Project,
			item.ID,
		); err != nil {
			return err
		}
	}

	for _, item := range facts {
		assetID, err := resolveFactAsset(ctx, tx, item)
		if err != nil {
			return err
		}
		if assetID == "" {
			continue
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_facts SET relation = ? WHERE id = ?`,
			"asset_id:"+assetID,
			item.ID,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_graph_nodes SET asset_id = ?, updated_at = ?
			 WHERE project_id = ? AND kind = 'fact' AND title = ?`,
			assetID,
			time.Now().UTC().Unix(),
			item.Project,
			item.Key,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func assetRiskScoreForSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 20
	default:
		return 0
	}
}

func (db *DB) listVulnerabilitiesMissingAssets(
	ctx context.Context,
) ([]vulnerabilityAssetBackfill, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, title, project_id, owner_user_id, target, severity
		 FROM vulnerabilities
		 WHERE TRIM(project_id) <> ''
			AND TRIM(target) <> ''
			AND TRIM(asset_id) = ''`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]vulnerabilityAssetBackfill, 0)
	for rows.Next() {
		var item vulnerabilityAssetBackfill
		if err := rows.Scan(
			&item.ID,
			&item.Title,
			&item.Project,
			&item.Owner,
			&item.Target,
			&item.Severity,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) listFactAssetRelations(ctx context.Context) ([]factAssetRelation, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT f.id, f.project_id, p.owner_user_id, f.key, f.relation
		 FROM project_facts f
		 JOIN projects p ON p.id = f.project_id
		 WHERE LOWER(TRIM(f.relation)) LIKE 'asset:%'
		    OR LOWER(TRIM(f.relation)) LIKE 'asset_id:%'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]factAssetRelation, 0)
	for rows.Next() {
		var item factAssetRelation
		if err := rows.Scan(
			&item.ID,
			&item.Project,
			&item.Owner,
			&item.Key,
			&item.Relation,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func resolveFactAsset(
	ctx context.Context,
	tx *sql.Tx,
	item factAssetRelation,
) (string, error) {
	relation := strings.TrimSpace(item.Relation)
	lower := strings.ToLower(relation)
	if strings.HasPrefix(lower, "asset_id:") {
		payload := strings.TrimSpace(relation[len("asset_id:"):])
		if payload == "" {
			return "", nil
		}
		var assetID string
		err := tx.QueryRowContext(
			ctx,
			`SELECT id FROM assets
			 WHERE id = ? AND project_id = ? AND owner_user_id = ?`,
			payload,
			item.Project,
			item.Owner,
		).Scan(&assetID)
		if NoRows(err) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return preferCanonicalFactAsset(ctx, tx, item, assetID)
	}
	if !strings.HasPrefix(lower, "asset:") {
		return "", nil
	}
	payload := strings.TrimSpace(relation[len("asset:"):])
	if payload == "" {
		return "", nil
	}
	var assetID string
	err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM assets
		 WHERE project_id = ? AND owner_user_id = ?
		   AND (
			id = ?
			OR LOWER(TRIM(value)) = LOWER(TRIM(?))
			OR LOWER(TRIM(name)) = LOWER(TRIM(?))
		   )
		 ORDER BY CASE
			WHEN id = ? THEN 0
			WHEN LOWER(TRIM(value)) = LOWER(TRIM(?)) THEN 1
			ELSE 2
		 END,
			updated_at DESC
		 LIMIT 1`,
		item.Project,
		item.Owner,
		payload,
		payload,
		payload,
		payload,
		payload,
	).Scan(&assetID)
	if NoRows(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return preferCanonicalFactAsset(ctx, tx, item, assetID)
}

func preferCanonicalFactAsset(
	ctx context.Context,
	tx *sql.Tx,
	item factAssetRelation,
	assetID string,
) (string, error) {
	var kind string
	var name string
	var value string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT kind, name, value FROM assets
		 WHERE id = ? AND project_id = ? AND owner_user_id = ?`,
		assetID,
		item.Project,
		item.Owner,
	).Scan(&kind, &name, &value); err != nil {
		if NoRows(err) {
			return "", nil
		}
		return "", err
	}
	if !strings.EqualFold(strings.TrimSpace(kind), "other") ||
		!strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(name)) {
		return assetID, nil
	}

	var canonicalID string
	err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM assets
		 WHERE project_id = ? AND owner_user_id = ? AND id <> ?
		   AND LOWER(TRIM(name)) = LOWER(TRIM(?))
		   AND LOWER(TRIM(kind)) <> 'other'
		   AND LOWER(TRIM(value)) <> LOWER(TRIM(name))
		 ORDER BY updated_at DESC
		 LIMIT 1`,
		item.Project,
		item.Owner,
		assetID,
		name,
	).Scan(&canonicalID)
	if NoRows(err) {
		return assetID, nil
	}
	if err != nil {
		return "", err
	}
	return canonicalID, nil
}

func ensureProjectAsset(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	ownerUserID string,
	value string,
	riskScore int,
) (string, error) {
	value = strings.TrimSpace(value)
	if projectID == "" || ownerUserID == "" || value == "" {
		return "", fmt.Errorf("补建资产缺少项目、用户或资产值")
	}

	var existingID string
	err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM assets
		 WHERE project_id = ? AND owner_user_id = ? AND LOWER(TRIM(value)) = LOWER(TRIM(?))
		 ORDER BY updated_at DESC LIMIT 1`,
		projectID,
		ownerUserID,
		value,
	).Scan(&existingID)
	if err == nil {
		return existingID, nil
	}
	if !NoRows(err) {
		return "", err
	}

	now := time.Now().UTC()
	assetID := newID()
	kind := inferAssetKind(value)
	if kind == "" {
		return "", nil
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, status,
			criticality, risk_score, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 'active', 'medium', ?, ?, ?)`,
		assetID,
		projectID,
		ownerUserID,
		value,
		kind,
		value,
		riskScore,
		now.Unix(),
		now.Unix(),
	); err != nil {
		return "", err
	}
	return assetID, nil
}

func inferAssetKind(value string) string {
	value = strings.TrimSpace(value)
	if _, err := NormalizeAssetValue("url", value); err == nil {
		return "url"
	}
	if _, err := NormalizeAssetValue("ip", value); err == nil {
		return "ip"
	}
	if _, err := NormalizeAssetValue("domain", value); err == nil {
		return "domain"
	}
	if _, err := NormalizeAssetValue("port", value); err == nil {
		return "port"
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return "host"
	}
	if host, err := NormalizeAssetValue("host", value); err == nil && !strings.Contains(host, ".") {
		return "host"
	}
	return ""
}
