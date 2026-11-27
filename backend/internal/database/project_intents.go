package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const derivedIntentTTL = 7 * 24 * time.Hour

type ProjectIntentFilter struct {
	ProjectID string
	Status    string
	Query     string
	AssetID   string
	Limit     int
	Offset    int
}

type ProjectIntent struct {
	GraphNode
	ExecutionState      string    `json:"executionState"`
	OutcomeState        string    `json:"outcomeState"`
	StateReason         string    `json:"stateReason"`
	Result              string    `json:"result"`
	Evidence            string    `json:"evidence"`
	EvidenceRefs        []string  `json:"evidenceRefs"`
	FindingID           string    `json:"findingId"`
	Attempts            int       `json:"attempts"`
	TestConfidence      int       `json:"testConfidence"`
	LastFinishedAt      time.Time `json:"lastFinishedAt"`
	LastWorkerSessionID string    `json:"lastWorkerSessionId"`
}

func (db *DB) expireDerivedProjectIntents(
	ctx context.Context,
	projectID string,
	now time.Time,
) (int64, error) {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'stopped',
			detail = CASE
				WHEN TRIM(detail) = '' THEN '系统派生意图超过 7 天未推进，已自动停止。'
				ELSE detail || char(10) || '系统派生意图超过 7 天未推进，已自动停止。'
			END,
			updated_at = ?
		 WHERE project_id = ?
		   AND kind = 'intent'
		   AND source IN ('blocked-follow-up', 'finding-follow-up')
		   AND status IN ('open', 'capacity_blocked')
		   AND created_at < ?`,
		now.UTC().Unix(),
		projectID,
		now.Add(-derivedIntentTTL).UTC().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) ListProjectIntentsPage(
	ctx context.Context,
	filter ProjectIntentFilter,
) ([]ProjectIntent, int, error) {
	filter.ProjectID = strings.TrimSpace(filter.ProjectID)
	if filter.ProjectID == "" {
		return nil, 0, fmt.Errorf("项目不能为空")
	}
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 50
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	where := []string{"n.project_id = ?", "n.kind = 'intent'"}
	args := []interface{}{filter.ProjectID}
	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" {
		where = append(where, "n.status = ?")
		args = append(args, status)
	}
	if assetID := strings.TrimSpace(filter.AssetID); assetID != "" {
		where = append(where, "n.asset_id = ?")
		args = append(args, assetID)
	}
	if query := strings.ToLower(strings.TrimSpace(filter.Query)); query != "" {
		pattern := "%" + escapeLikePattern(query) + "%"
		where = append(where, `(
			LOWER(n.title) LIKE ? ESCAPE '\'
			OR LOWER(n.detail) LIKE ? ESCAPE '\'
			OR LOWER(n.source) LIKE ? ESCAPE '\'
			OR LOWER(n.source_ref_id) LIKE ? ESCAPE '\'
			OR LOWER(a.name) LIKE ? ESCAPE '\'
			OR LOWER(a.value) LIKE ? ESCAPE '\'
		)`)
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern)
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM project_graph_nodes n
		 LEFT JOIN assets a ON a.id = n.asset_id AND a.project_id = n.project_id
		 WHERE `+whereSQL,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append([]interface{}(nil), args...)
	queryArgs = append(queryArgs, filter.Limit, filter.Offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT n.id, n.project_id, n.kind, n.title, n.detail, n.status, n.confidence,
			n.severity, n.asset_id, n.source, n.source_ref_id, n.pos_x, n.pos_y,
			n.created_at, n.updated_at,
			COALESCE(r.execution_state, ''), COALESCE(r.outcome_state, ''),
			COALESCE(r.state_reason, ''), COALESCE(r.result, ''),
			COALESCE(r.evidence, ''), COALESCE(r.evidence_refs, '[]'),
			COALESCE(r.finding_id, ''), COALESCE(r.attempts, 0),
			COALESCE(r.confidence, 0), COALESCE(r.last_finished_at, 0),
			COALESCE(r.last_worker_session_id, '')
		 FROM project_graph_nodes n
		 LEFT JOIN assets a ON a.id = n.asset_id AND a.project_id = n.project_id
		 LEFT JOIN project_test_results r ON r.id = (
		 	SELECT latest.id FROM project_test_results latest
		 	WHERE latest.project_id = n.project_id AND latest.intent_id = n.id
		 	ORDER BY latest.updated_at DESC, latest.id DESC
		 	LIMIT 1
		 )
		 WHERE `+whereSQL+`
		 ORDER BY CASE n.status
			WHEN 'running' THEN 0
			WHEN 'open' THEN 1
			WHEN 'blocked' THEN 2
			WHEN 'capacity_blocked' THEN 3
			WHEN 'exhausted' THEN 4
			WHEN 'done' THEN 5
			WHEN 'stopped' THEN 6
			ELSE 9 END,
			n.confidence DESC, n.updated_at DESC, n.id ASC
		 LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ProjectIntent, 0, filter.Limit)
	for rows.Next() {
		item, scanErr := scanProjectIntent(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func scanProjectIntent(scanner rowScanner) (ProjectIntent, error) {
	var item ProjectIntent
	var evidenceRefs string
	var createdAt, updatedAt, lastFinishedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.Kind,
		&item.Title,
		&item.Detail,
		&item.Status,
		&item.Confidence,
		&item.Severity,
		&item.AssetID,
		&item.Source,
		&item.SourceRefID,
		&item.PosX,
		&item.PosY,
		&createdAt,
		&updatedAt,
		&item.ExecutionState,
		&item.OutcomeState,
		&item.StateReason,
		&item.Result,
		&item.Evidence,
		&evidenceRefs,
		&item.FindingID,
		&item.Attempts,
		&item.TestConfidence,
		&lastFinishedAt,
		&item.LastWorkerSessionID,
	)
	if err != nil {
		return item, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	item.EvidenceRefs = decodeEvidenceRefs(evidenceRefs)
	if lastFinishedAt > 0 {
		item.LastFinishedAt = time.Unix(lastFinishedAt, 0)
	}
	return item, nil
}
