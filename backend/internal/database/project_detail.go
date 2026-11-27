package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type AttackStep struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	StepOrder   int       `json:"stepOrder"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Technique   string    `json:"technique"`
	Evidence    string    `json:"evidence"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type ProjectCounts struct {
	Facts                  int   `json:"facts"`
	PendingIntents         int   `json:"pendingIntents"`
	TotalIntents           int   `json:"totalIntents"`
	CapacityBlockedIntents int   `json:"capacityBlockedIntents"`
	BlockedIntents         int   `json:"blockedIntents"`
	IntentCapacity         int   `json:"intentCapacity"`
	OldestIntentAt         int64 `json:"oldestIntentAt"`
	EvidenceGaps           int   `json:"evidenceGaps"`
	AttackSteps            int   `json:"attackSteps"`
	Assets                 int   `json:"assets"`
	Conversations          int   `json:"conversations"`
	Vulnerabilities        int   `json:"vulnerabilities"`
	PromptTokens           int   `json:"promptTokens"`
	CompletionTokens       int   `json:"completionTokens"`
	TotalTokens            int   `json:"totalTokens"`
	TokenUsageEstimated    bool  `json:"tokenUsageEstimated"`
}

const ProjectIntentCapacityLimit = 100

type ProjectWithCounts struct {
	Project
	Counts ProjectCounts `json:"counts"`
}

type ProjectListFilter struct {
	OwnerUserID string
	Search      string
	Status      string
	RiskOnly    bool
	Sort        string
	Limit       int
	Offset      int
}

type ProjectListStats struct {
	Total  int `json:"total"`
	Active int `json:"active"`
	Paused int `json:"paused"`
	Done   int `json:"done"`
	Risk   int `json:"risk"`
}

func (db *DB) ProjectSummary(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (*ProjectCounts, error) {
	counts := &ProjectCounts{}
	queries := []struct {
		statement string
		target    *int
	}{
		{`SELECT COUNT(*) FROM project_facts WHERE project_id = ?`, &counts.Facts},
		{`SELECT COUNT(*) FROM project_graph_nodes
		  WHERE project_id = ? AND kind = 'intent' AND status IN ('open', 'running')`, &counts.PendingIntents},
		{`SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = ?`, &counts.AttackSteps},
		{`SELECT COUNT(*) FROM assets
		  WHERE project_id = ?
		    AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'source')`, &counts.Assets},
		{`SELECT COUNT(*) FROM conversations WHERE project_id = ?`, &counts.Conversations},
		{`SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?`, &counts.Vulnerabilities},
	}
	for _, query := range queries {
		if err := db.QueryRowContext(ctx, query.statement, projectID).Scan(query.target); err != nil {
			return nil, err
		}
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COALESCE(SUM(CASE WHEN status = 'capacity_blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(MIN(CASE WHEN status IN ('open', 'running') THEN created_at END), 0),
			COUNT(*)
		 FROM project_graph_nodes
		 WHERE project_id = ? AND kind = 'intent'`,
		projectID,
	).Scan(
		&counts.CapacityBlockedIntents,
		&counts.BlockedIntents,
		&counts.OldestIntentAt,
		&counts.TotalIntents,
	); err != nil {
		return nil, err
	}
	counts.IntentCapacity = ProjectIntentCapacityLimit
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			(SELECT COUNT(*) FROM project_facts f
			 WHERE f.project_id = ?
			   AND TRIM(f.evidence) = ''
			   AND COALESCE(f.subject_type, '') NOT IN ('audit_scope', 'audit_checkpoint')
			   AND NOT (f.subject_type = 'audit_cell' AND f.predicate = 'coverage'))
			+
			(SELECT COUNT(*) FROM vulnerabilities v
			 WHERE v.project_id = ?
			   AND TRIM(v.evidence) = ''
			   AND (TRIM(v.evidence_refs) = '' OR TRIM(v.evidence_refs) = '[]'))`,
		projectID,
		projectID,
	).Scan(&counts.EvidenceGaps); err != nil {
		return nil, err
	}
	var estimated int
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COALESCE(SUM(t.prompt_tokens), 0),
			COALESCE(SUM(t.completion_tokens), 0),
			COALESCE(SUM(t.total_tokens), 0),
			COALESCE(MAX(t.estimated), 0)
		 FROM token_usage t
			 WHERE t.project_id = ? AND t.user_id = ?`,
		projectID,
		ownerUserID,
	).Scan(
		&counts.PromptTokens,
		&counts.CompletionTokens,
		&counts.TotalTokens,
		&estimated,
	); err != nil {
		return nil, err
	}
	counts.TokenUsageEstimated = estimated != 0
	return counts, nil
}

func (db *DB) ListProjectsWithCounts(
	ctx context.Context,
	ownerUserID string,
) ([]ProjectWithCounts, error) {
	items, _, err := db.ListProjectsWithCountsPage(ctx, ownerUserID, 100, "")
	return items, err
}

func (db *DB) ListProjectsWithCountsPage(
	ctx context.Context,
	ownerUserID string,
	limit int,
	beforeProjectID string,
) ([]ProjectWithCounts, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `WITH page AS (
			SELECT
				p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
				p.created_at, p.updated_at, p.rowid AS project_rowid
			FROM projects p
			WHERE p.owner_user_id = ?`
	args := []interface{}{ownerUserID}
	if beforeProjectID = strings.TrimSpace(beforeProjectID); beforeProjectID != "" {
		var updatedAt int64
		var ordering int64
		err := db.QueryRowContext(
			ctx,
			`SELECT updated_at, rowid FROM projects WHERE id = ? AND owner_user_id = ?`,
			beforeProjectID,
			ownerUserID,
		).Scan(&updatedAt, &ordering)
		if errors.Is(err, sql.ErrNoRows) {
			return []ProjectWithCounts{}, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		query += ` AND (p.updated_at < ? OR (p.updated_at = ? AND p.rowid < ?))`
		args = append(args, updatedAt, updatedAt, ordering)
	}
	query += `
			ORDER BY p.updated_at DESC, p.rowid DESC
			LIMIT ?
		)
		SELECT
			p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
			p.created_at, p.updated_at,
			(SELECT COUNT(*) FROM project_graph_nodes g
			 WHERE g.project_id = p.id AND g.kind = 'intent' AND g.status IN ('open', 'running')),
			(SELECT COUNT(*) FROM project_facts f
			 WHERE f.project_id = p.id
			   AND TRIM(f.evidence) = ''
			   AND COALESCE(f.subject_type, '') NOT IN ('audit_scope', 'audit_checkpoint')
			   AND NOT (f.subject_type = 'audit_cell' AND f.predicate = 'coverage'))
			+
			(SELECT COUNT(*) FROM vulnerabilities v
			 WHERE v.project_id = p.id
			   AND TRIM(v.evidence) = ''
			   AND (TRIM(v.evidence_refs) = '' OR TRIM(v.evidence_refs) = '[]')),
			(SELECT COUNT(*) FROM project_facts f WHERE f.project_id = p.id),
			(SELECT COUNT(*) FROM project_graph_nodes g WHERE g.project_id = p.id),
			(SELECT COUNT(*) FROM assets a
			 WHERE a.project_id = p.id
			   AND LOWER(TRIM(a.kind)) IN ('domain', 'ip', 'url', 'source')),
			(SELECT COUNT(*) FROM conversations c WHERE c.project_id = p.id),
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_id = p.id),
			COALESCE(SUM(t.prompt_tokens), 0),
			COALESCE(SUM(t.completion_tokens), 0),
			COALESCE(SUM(t.total_tokens), 0),
			COALESCE(MAX(t.estimated), 0)
		FROM page p
		LEFT JOIN token_usage t
		  ON t.project_id = p.id AND t.user_id = p.owner_user_id
		GROUP BY p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
			p.created_at, p.updated_at, p.project_rowid
		ORDER BY p.updated_at DESC, p.project_rowid DESC`
	args = append(args, limit+1)

	rows, err := db.QueryContext(
		ctx,
		query,
		args...,
	)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	items := make([]ProjectWithCounts, 0)
	for rows.Next() {
		var item ProjectWithCounts
		var createdAt int64
		var updatedAt int64
		var estimated int
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.Name,
			&item.Description,
			&item.Goals,
			&item.Scope,
			&item.Status,
			&createdAt,
			&updatedAt,
			&item.Counts.PendingIntents,
			&item.Counts.EvidenceGaps,
			&item.Counts.Facts,
			&item.Counts.AttackSteps,
			&item.Counts.Assets,
			&item.Counts.Conversations,
			&item.Counts.Vulnerabilities,
			&item.Counts.PromptTokens,
			&item.Counts.CompletionTokens,
			&item.Counts.TotalTokens,
			&estimated,
		); err != nil {
			return nil, false, err
		}
		item.Counts.TokenUsageEstimated = estimated != 0
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

func (db *DB) ListProjectsWithCountsOffset(
	ctx context.Context,
	filter ProjectListFilter,
) ([]ProjectWithCounts, int, ProjectListStats, error) {
	var stats ProjectListStats
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'paused' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN EXISTS (
				SELECT 1 FROM vulnerabilities v WHERE v.project_id = projects.id
			) THEN 1 ELSE 0 END), 0)
		 FROM projects WHERE owner_user_id = ?`,
		filter.OwnerUserID,
	).Scan(
		&stats.Total,
		&stats.Active,
		&stats.Paused,
		&stats.Done,
		&stats.Risk,
	); err != nil {
		return nil, 0, stats, err
	}

	where, args := buildProjectListWhere(filter)
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM projects p`+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, stats, err
	}
	order := projectListOrder(filter.Sort)

	query := `WITH page AS (
			SELECT
				p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
				p.created_at, p.updated_at, p.rowid AS project_rowid
			FROM projects p` + where + `
			ORDER BY ` + order + `
			LIMIT ? OFFSET ?
		)
		SELECT
			p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
			p.created_at, p.updated_at,
			(SELECT COUNT(*) FROM project_graph_nodes g
			 WHERE g.project_id = p.id AND g.kind = 'intent' AND g.status IN ('open', 'running')),
			(SELECT COUNT(*) FROM project_facts f
			 WHERE f.project_id = p.id
			   AND TRIM(f.evidence) = ''
			   AND COALESCE(f.subject_type, '') NOT IN ('audit_scope', 'audit_checkpoint')
			   AND NOT (f.subject_type = 'audit_cell' AND f.predicate = 'coverage'))
			+
			(SELECT COUNT(*) FROM vulnerabilities v
			 WHERE v.project_id = p.id
			   AND TRIM(v.evidence) = ''
			   AND (TRIM(v.evidence_refs) = '' OR TRIM(v.evidence_refs) = '[]')),
			(SELECT COUNT(*) FROM project_facts f WHERE f.project_id = p.id),
			(SELECT COUNT(*) FROM project_graph_nodes g WHERE g.project_id = p.id),
			(SELECT COUNT(*) FROM assets a
			 WHERE a.project_id = p.id
			   AND LOWER(TRIM(a.kind)) IN ('domain', 'ip', 'url', 'source')),
			(SELECT COUNT(*) FROM conversations c WHERE c.project_id = p.id),
			(SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_id = p.id),
			COALESCE(SUM(t.prompt_tokens), 0),
			COALESCE(SUM(t.completion_tokens), 0),
			COALESCE(SUM(t.total_tokens), 0),
			COALESCE(MAX(t.estimated), 0)
		FROM page p
		LEFT JOIN token_usage t
		  ON t.project_id = p.id AND t.user_id = p.owner_user_id
		GROUP BY p.id, p.owner_user_id, p.name, p.description, p.goals, p.scope, p.status,
			p.created_at, p.updated_at, p.project_rowid
		ORDER BY ` + order
	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return nil, 0, stats, err
	}
	defer rows.Close()

	items := make([]ProjectWithCounts, 0)
	for rows.Next() {
		var item ProjectWithCounts
		var createdAt int64
		var updatedAt int64
		var estimated int
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.Name,
			&item.Description,
			&item.Goals,
			&item.Scope,
			&item.Status,
			&createdAt,
			&updatedAt,
			&item.Counts.PendingIntents,
			&item.Counts.EvidenceGaps,
			&item.Counts.Facts,
			&item.Counts.AttackSteps,
			&item.Counts.Assets,
			&item.Counts.Conversations,
			&item.Counts.Vulnerabilities,
			&item.Counts.PromptTokens,
			&item.Counts.CompletionTokens,
			&item.Counts.TotalTokens,
			&estimated,
		); err != nil {
			return nil, 0, stats, err
		}
		item.Counts.TokenUsageEstimated = estimated != 0
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, stats, err
	}
	return items, total, stats, nil
}

func projectListOrder(sort string) string {
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "updated_asc":
		return "p.updated_at ASC, project_rowid ASC"
	case "name_asc":
		return "p.name COLLATE NOCASE ASC, p.updated_at DESC, project_rowid DESC"
	case "name_desc":
		return "p.name COLLATE NOCASE DESC, p.updated_at DESC, project_rowid DESC"
	case "status_asc":
		return "p.status COLLATE NOCASE ASC, p.updated_at DESC, project_rowid DESC"
	case "risk_desc":
		return `(SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_id = p.id) DESC,
			p.updated_at DESC, project_rowid DESC`
	case "risk_asc":
		return `(SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_id = p.id) ASC,
			p.updated_at DESC, project_rowid DESC`
	default:
		return "p.updated_at DESC, project_rowid DESC"
	}
}

func buildProjectListWhere(filter ProjectListFilter) (string, []interface{}) {
	clauses := []string{"p.owner_user_id = ?"}
	args := []interface{}{filter.OwnerUserID}
	if value := strings.TrimSpace(filter.Status); value != "" {
		clauses = append(clauses, "p.status = ?")
		args = append(args, value)
	}
	if value := strings.TrimSpace(filter.Search); value != "" {
		pattern := "%" + escapeLikePattern(value) + "%"
		clauses = append(
			clauses,
			`(p.name LIKE ? ESCAPE '\' OR p.description LIKE ? ESCAPE '\')`,
		)
		args = append(args, pattern, pattern)
	}
	if filter.RiskOnly {
		clauses = append(
			clauses,
			`EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.project_id = p.id)`,
		)
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func normalizeProjectPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func (db *DB) ListProjectAssets(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) ([]Asset, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets
		 WHERE project_id = ? AND owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')
		 ORDER BY updated_at DESC`,
		projectID,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Asset, 0)
	for rows.Next() {
		var item Asset
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Name,
			&item.Kind,
			&item.Value,
			&item.NormalizedValue,
			&item.QualityStatus,
			&item.Status,
			&item.Source,
			&item.Criticality,
			&item.RiskScore,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListProjectAssetsPage(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	limit int,
	offset int,
) ([]Asset, int, error) {
	limit, offset = normalizeProjectPage(limit, offset)
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets
		 WHERE project_id = ? AND owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')`,
		projectID,
		ownerUserID,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets
		 WHERE project_id = ? AND owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')
		 ORDER BY updated_at DESC, rowid DESC
		 LIMIT ? OFFSET ?`,
		projectID,
		ownerUserID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]Asset, 0)
	for rows.Next() {
		var item Asset
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Name,
			&item.Kind,
			&item.Value,
			&item.NormalizedValue,
			&item.QualityStatus,
			&item.Status,
			&item.Source,
			&item.Criticality,
			&item.RiskScore,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (db *DB) ListProjectConversations(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) ([]Conversation, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, project_id, asset_id, execution_lane, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at
		 FROM conversations
		 WHERE project_id = ? AND owner_user_id = ?
		 ORDER BY updated_at DESC`,
		projectID,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Conversation, 0)
	for rows.Next() {
		var item Conversation
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.ProjectID,
			&item.AssetID,
			&item.ExecutionLane,
			&item.Kind,
			&item.ParentConversationID,
			&item.BatchID,
			&item.AgentRoleID,
			&item.Title,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListProjectConversationsPage(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	limit int,
	offset int,
) ([]Conversation, int, error) {
	limit, offset = normalizeProjectPage(limit, offset)
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM conversations
		 WHERE project_id = ? AND owner_user_id = ? AND parent_conversation_id = ''`,
		projectID,
		ownerUserID,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, project_id, asset_id, execution_lane, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at
		 FROM conversations
		 WHERE project_id = ? AND owner_user_id = ? AND parent_conversation_id = ''
		 ORDER BY updated_at DESC, rowid DESC
		 LIMIT ? OFFSET ?`,
		projectID,
		ownerUserID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]Conversation, 0)
	for rows.Next() {
		var item Conversation
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.ProjectID,
			&item.AssetID,
			&item.ExecutionLane,
			&item.Kind,
			&item.ParentConversationID,
			&item.BatchID,
			&item.AgentRoleID,
			&item.Title,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (db *DB) ListProjectAttackSteps(
	ctx context.Context,
	projectID string,
) ([]AttackStep, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, step_order, name, description, status, severity,
			technique, evidence, created_at, updated_at
		 FROM project_attack_steps
		 WHERE project_id = ?
		 ORDER BY step_order ASC, created_at ASC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AttackStep, 0)
	for rows.Next() {
		item, err := scanAttackStep(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) CreateProjectAttackStep(ctx context.Context, step AttackStep) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO project_attack_steps (
			id, project_id, step_order, name, description, status, severity,
			technique, evidence, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		step.ID,
		step.ProjectID,
		step.StepOrder,
		step.Name,
		step.Description,
		step.Status,
		step.Severity,
		step.Technique,
		step.Evidence,
		step.CreatedAt.Unix(),
		step.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpdateProjectAttackStep(ctx context.Context, step AttackStep) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_attack_steps
		 SET step_order = ?, name = ?, description = ?, status = ?, severity = ?,
			technique = ?, evidence = ?, updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		step.StepOrder,
		step.Name,
		step.Description,
		step.Status,
		step.Severity,
		step.Technique,
		step.Evidence,
		step.UpdatedAt.Unix(),
		step.ID,
		step.ProjectID,
	)
	return requireAffected(result, err)
}

func (db *DB) DeleteProjectAttackStep(ctx context.Context, id, projectID string) error {
	result, err := db.ExecContext(
		ctx,
		`DELETE FROM project_attack_steps WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	)
	return requireAffected(result, err)
}

func (db *DB) NextAttackStepOrder(ctx context.Context, projectID string) (int, error) {
	var next int
	err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(MAX(step_order), 0) + 1 FROM project_attack_steps WHERE project_id = ?`,
		projectID,
	).Scan(&next)
	return next, err
}

func (db *DB) ReorderProjectAttackSteps(
	ctx context.Context,
	projectID string,
	ids []string,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(
		ctx,
		`SELECT id FROM project_attack_steps WHERE project_id = ?`,
		projectID,
	)
	if err != nil {
		return err
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		existing[id] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(existing) != len(ids) {
		return fmt.Errorf("排序必须包含项目全部攻击步骤")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !existing[id] || seen[id] {
			return fmt.Errorf("攻击步骤排序包含无效或重复 ID")
		}
		seen[id] = true
	}

	now := time.Now().UTC().Unix()
	for index, id := range ids {
		result, err := tx.ExecContext(
			ctx,
			`UPDATE project_attack_steps SET step_order = ?, updated_at = ?
			 WHERE id = ? AND project_id = ?`,
			index+1,
			now,
			id,
			projectID,
		)
		if err := requireAffected(result, err); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetProjectAttackStep(
	ctx context.Context,
	id string,
	projectID string,
) (*AttackStep, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, project_id, step_order, name, description, status, severity,
			technique, evidence, created_at, updated_at
		 FROM project_attack_steps WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	)
	step, err := scanAttackStep(row)
	if err != nil {
		return nil, err
	}
	return &step, nil
}

func scanAttackStep(scanner rowScanner) (AttackStep, error) {
	var step AttackStep
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&step.ID,
		&step.ProjectID,
		&step.StepOrder,
		&step.Name,
		&step.Description,
		&step.Status,
		&step.Severity,
		&step.Technique,
		&step.Evidence,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return step, err
	}
	step.CreatedAt = time.Unix(createdAt, 0)
	step.UpdatedAt = time.Unix(updatedAt, 0)
	return step, nil
}
