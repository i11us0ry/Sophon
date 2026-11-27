package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type EvidenceGap struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	AssetID      string    `json:"assetId"`
	Title        string    `json:"title"`
	Summary      string    `json:"summary"`
	FactType     string    `json:"factType"`
	Severity     string    `json:"severity"`
	Status       string    `json:"status"`
	Verification string    `json:"verificationState"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type EvidenceGapFilter struct {
	ProjectID string
	AssetID   string
	Kind      string
	Status    string
	Query     string
	Limit     int
	Offset    int
}

func (db *DB) ListEvidenceGaps(
	ctx context.Context,
	filter EvidenceGapFilter,
) ([]EvidenceGap, int, error) {
	filter.ProjectID = strings.TrimSpace(filter.ProjectID)
	if filter.ProjectID == "" {
		return nil, 0, fmt.Errorf("项目不能为空")
	}
	limit, offset := normalizeProjectPage(filter.Limit, filter.Offset)
	factWhere, factArgs := evidenceFactWhere(filter)
	findingWhere, findingArgs := evidenceFindingWhere(filter)
	countQuery := `SELECT COUNT(*) FROM (
		SELECT f.id FROM project_facts f
		LEFT JOIN assets a ON a.id = f.asset_id AND a.project_id = f.project_id
		WHERE ` + factWhere + `
		UNION ALL
		SELECT v.id FROM vulnerabilities v
		LEFT JOIN assets a ON a.id = v.asset_id AND a.project_id = v.project_id
		WHERE ` + findingWhere + `
	)`
	countArgs := append(append([]interface{}{}, factArgs...), findingArgs...)
	var total int
	if err := db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}
	pageArgs := append(append([]interface{}{}, countArgs...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, kind, asset_id, title, summary, fact_type, severity, status,
		        verification_state, updated_at
		 FROM (
			SELECT f.id, 'fact' AS kind, f.asset_id, f.key AS title,
			       COALESCE(NULLIF(f.summary, ''), f.value) AS summary,
			       f.fact_type, '' AS severity, 'missing_evidence' AS status,
			       '' AS verification_state, f.updated_at
			FROM project_facts f
			LEFT JOIN assets a ON a.id = f.asset_id AND a.project_id = f.project_id
			WHERE `+factWhere+`
			UNION ALL
			SELECT v.id, 'finding' AS kind, v.asset_id, v.title,
			       COALESCE(NULLIF(v.target, ''), v.vulnerability_type) AS summary,
			       v.vulnerability_type AS fact_type, v.severity, 'missing_evidence' AS status,
			       v.verification_state, v.updated_at
			FROM vulnerabilities v
			LEFT JOIN assets a ON a.id = v.asset_id AND a.project_id = v.project_id
			WHERE `+findingWhere+`
		 ) gaps
		 ORDER BY updated_at DESC, id ASC
		 LIMIT ? OFFSET ?`,
		pageArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]EvidenceGap, 0, limit)
	for rows.Next() {
		var item EvidenceGap
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.Kind,
			&item.AssetID,
			&item.Title,
			&item.Summary,
			&item.FactType,
			&item.Severity,
			&item.Status,
			&item.Verification,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func evidenceFactWhere(filter EvidenceGapFilter) (string, []interface{}) {
	where := []string{
		"f.project_id = ?",
		"f.valid_to = 0",
		"TRIM(f.evidence) = ''",
		"LOWER(TRIM(f.subject_type)) NOT IN ('audit_scope', 'audit_checkpoint')",
	}
	args := []interface{}{strings.TrimSpace(filter.ProjectID)}
	if assetID := strings.TrimSpace(filter.AssetID); assetID != "" {
		where = append(where, "(f.asset_id = ? OR f.asset_id = '')")
		args = append(args, assetID)
	}
	if kind := strings.ToLower(strings.TrimSpace(filter.Kind)); kind == "finding" {
		where = append(where, "1 = 0")
	}
	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" &&
		status != "all" && status != "missing_evidence" {
		where = append(where, "1 = 0")
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern := "%" + escapeLikePattern(strings.ToLower(query)) + "%"
		where = append(where, `(
			LOWER(f.key) LIKE ? ESCAPE '\' OR LOWER(f.summary) LIKE ? ESCAPE '\' OR LOWER(f.value) LIKE ? ESCAPE '\'
			OR LOWER(f.fact_type) LIKE ? ESCAPE '\' OR LOWER(a.name) LIKE ? ESCAPE '\' OR LOWER(a.value) LIKE ? ESCAPE '\'
		)`)
		for range 6 {
			args = append(args, pattern)
		}
	}
	return strings.Join(where, " AND "), args
}

func evidenceFindingWhere(filter EvidenceGapFilter) (string, []interface{}) {
	where := []string{
		"v.project_id = ?",
		"TRIM(v.evidence) = ''",
		"(TRIM(v.evidence_refs) = '' OR TRIM(v.evidence_refs) = '[]')",
	}
	args := []interface{}{strings.TrimSpace(filter.ProjectID)}
	if assetID := strings.TrimSpace(filter.AssetID); assetID != "" {
		where = append(where, "v.asset_id = ?")
		args = append(args, assetID)
	}
	if kind := strings.ToLower(strings.TrimSpace(filter.Kind)); kind == "fact" {
		where = append(where, "1 = 0")
	}
	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" &&
		status != "all" && status != "missing_evidence" {
		where = append(where, "1 = 0")
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern := "%" + escapeLikePattern(strings.ToLower(query)) + "%"
		where = append(where, `(
			LOWER(v.title) LIKE ? ESCAPE '\' OR LOWER(v.target) LIKE ? ESCAPE '\'
			OR LOWER(v.vulnerability_type) LIKE ? ESCAPE '\' OR LOWER(v.description) LIKE ? ESCAPE '\'
			OR LOWER(a.name) LIKE ? ESCAPE '\' OR LOWER(a.value) LIKE ? ESCAPE '\'
		)`)
		for range 6 {
			args = append(args, pattern)
		}
	}
	return strings.Join(where, " AND "), args
}
