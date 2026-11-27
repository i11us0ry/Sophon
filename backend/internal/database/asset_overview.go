package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type AssetOverview struct {
	ID                 string    `json:"id"`
	ProjectID          string    `json:"projectId"`
	Name               string    `json:"name"`
	Kind               string    `json:"kind"`
	Value              string    `json:"value"`
	QualityStatus      string    `json:"qualityStatus"`
	Status             string    `json:"status"`
	Source             string    `json:"source"`
	Criticality        string    `json:"criticality"`
	RiskScore          int       `json:"riskScore"`
	AuthorizationState string    `json:"authorizationState"`
	WorkState          string    `json:"workState"`
	Priority           int       `json:"priority"`
	StateReason        string    `json:"stateReason"`
	CoverageStatus     string    `json:"coverageStatus"`
	TestsTotal         int       `json:"testsTotal"`
	TestsCovered       int       `json:"testsCovered"`
	Findings           int       `json:"findings"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type AssetOverviewFilter struct {
	State              string
	Kind               string
	AuthorizationState string
	QualityStatus      string
	Search             string
	Limit              int
	Offset             int
}

func (db *DB) ListProjectAssetOverview(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	filter AssetOverviewFilter,
) ([]AssetOverview, int, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return nil, 0, fmt.Errorf("项目或用户不能为空")
	}
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return nil, 0, err
	}
	where, args := buildAssetOverviewWhere(projectID, ownerUserID, filter)
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM assets a
		 LEFT JOIN project_asset_work w
		   ON w.project_id = a.project_id AND w.owner_user_id = a.owner_user_id AND w.asset_id = a.id`+
			where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit, offset := normalizeProjectPage(filter.Limit, filter.Offset)
	query := `SELECT a.id, a.project_id, a.name, a.kind, a.value,
	                 a.quality_status, a.status, a.source, a.criticality, a.risk_score,
	                 COALESCE(w.authorization_state, 'discovered'),
	                 COALESCE(w.work_state, 'queued'),
	                 COALESCE(w.priority, 0),
	                 COALESCE(w.state_reason, ''),
	                 a.updated_at
	          FROM assets a
	          LEFT JOIN project_asset_work w
	            ON w.project_id = a.project_id AND w.owner_user_id = a.owner_user_id AND w.asset_id = a.id` +
		where +
		` ORDER BY CASE COALESCE(w.work_state, 'queued')
		     WHEN 'active' THEN 0
		     WHEN 'testing' THEN 1
		     WHEN 'reopened' THEN 2
		     WHEN 'queued' THEN 3
		     WHEN 'needs_followup' THEN 4
		     WHEN 'awaiting_user' THEN 5
		     WHEN 'blocked' THEN 6
		     WHEN 'complete' THEN 7
		     ELSE 8
		   END,
		   COALESCE(w.priority, a.risk_score) DESC,
		   a.updated_at DESC
		   LIMIT ? OFFSET ?`
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]AssetOverview, 0)
	for rows.Next() {
		var item AssetOverview
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.Name,
			&item.Kind,
			&item.Value,
			&item.QualityStatus,
			&item.Status,
			&item.Source,
			&item.Criticality,
			&item.RiskScore,
			&item.AuthorizationState,
			&item.WorkState,
			&item.Priority,
			&item.StateReason,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	coverage, err := db.ProjectCoverage(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, 0, err
	}
	coverageByAsset := make(map[string]AssetCoverageState, len(coverage.AssetCoverage))
	for _, state := range coverage.AssetCoverage {
		coverageByAsset[state.AssetID] = state
	}
	for index := range items {
		state, ok := coverageByAsset[items[index].ID]
		if !ok {
			continue
		}
		items[index].CoverageStatus = state.Status
		items[index].TestsTotal = state.TestsTotal
		items[index].TestsCovered = state.TestsCovered
		items[index].Findings = state.Findings
	}
	return items, total, nil
}

func buildAssetOverviewWhere(
	projectID string,
	ownerUserID string,
	filter AssetOverviewFilter,
) (string, []interface{}) {
	clauses := []string{
		"a.project_id = ?",
		"a.owner_user_id = ?",
		"LOWER(TRIM(a.kind)) IN ('domain', 'ip', 'url', 'host', 'source')",
	}
	args := []interface{}{projectID, ownerUserID}
	kind := strings.ToLower(strings.TrimSpace(filter.Kind))
	if kind != "" {
		clauses = append(clauses, "LOWER(TRIM(a.kind)) = ?")
		args = append(args, kind)
	}
	quality := strings.ToLower(strings.TrimSpace(filter.QualityStatus))
	if quality != "" {
		clauses = append(clauses, "LOWER(TRIM(a.quality_status)) = ?")
		args = append(args, quality)
	} else {
		clauses = append(clauses, "COALESCE(NULLIF(TRIM(a.quality_status), ''), 'valid') <> ?")
		args = append(args, AssetQualityCrossTypeDuplicate)
	}
	authorization := strings.ToLower(strings.TrimSpace(filter.AuthorizationState))
	if authorization != "" {
		clauses = append(clauses, "LOWER(TRIM(COALESCE(w.authorization_state, 'discovered'))) = ?")
		args = append(args, authorization)
	}
	switch strings.ToLower(strings.TrimSpace(filter.State)) {
	case "", "all":
	case "pending":
		clauses = append(
			clauses,
			"COALESCE(w.authorization_state, 'discovered') = 'authorized' AND COALESCE(w.work_state, 'queued') IN ('queued', 'reopened', 'needs_followup')",
		)
	case "active":
		clauses = append(clauses, "COALESCE(w.work_state, 'queued') IN ('active', 'testing')")
	case "blocked":
		clauses = append(clauses, "COALESCE(w.work_state, 'queued') IN ('blocked', 'awaiting_user')")
	case "complete":
		clauses = append(clauses, "COALESCE(w.work_state, 'queued') = 'complete'")
	}
	search := strings.TrimSpace(filter.Search)
	if search != "" {
		pattern := "%" + escapeLikePattern(search) + "%"
		clauses = append(
			clauses,
			`(a.name LIKE ? ESCAPE '\' OR a.value LIKE ? ESCAPE '\' OR a.source LIKE ? ESCAPE '\')`,
		)
		args = append(args, pattern, pattern, pattern)
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
