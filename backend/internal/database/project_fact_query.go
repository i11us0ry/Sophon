package database

import (
	"context"
	"fmt"
	"strings"
)

type ProjectFactFilter struct {
	ProjectID string
	AssetID   string
	FactType  string
	Status    string
	Query     string
	Limit     int
	Offset    int
}

func (db *DB) ListProjectFactsPageFiltered(
	ctx context.Context,
	filter ProjectFactFilter,
) ([]ProjectFact, int, error) {
	filter.ProjectID = strings.TrimSpace(filter.ProjectID)
	filter.AssetID = strings.TrimSpace(filter.AssetID)
	if filter.ProjectID == "" {
		return nil, 0, fmt.Errorf("项目不能为空")
	}
	limit, offset := normalizeProjectPage(filter.Limit, filter.Offset)
	where := []string{"f.project_id = ?", "f.valid_to = 0"}
	args := []interface{}{filter.ProjectID}
	if filter.AssetID != "" {
		where = append(where, "(f.asset_id = ? OR f.asset_id = '')")
		args = append(args, filter.AssetID)
	}
	if factType := strings.ToLower(strings.TrimSpace(filter.FactType)); factType != "" {
		where = append(where, "(LOWER(TRIM(f.fact_type)) = ? OR LOWER(TRIM(f.memory_kind)) = ?)")
		args = append(args, factType, factType)
	}
	switch strings.ToLower(strings.TrimSpace(filter.Status)) {
	case "", "all":
	case "with_evidence", "evidence":
		where = append(where, "TRIM(f.evidence) <> ''")
	case "missing_evidence":
		where = append(where, "TRIM(f.evidence) = ''")
	case "tainted":
		where = append(where, "f.tainted = 1")
	case "conflict", "conflicted":
		where = append(where, "TRIM(f.contradicted_by) <> ''")
	case "pinned":
		where = append(where, "f.pinned = 1")
	default:
		return nil, 0, fmt.Errorf("事实状态不合法")
	}
	if query := strings.TrimSpace(filter.Query); query != "" {
		pattern := "%" + escapeLikePattern(strings.ToLower(query)) + "%"
		where = append(where, `(
			LOWER(f.key) LIKE ? ESCAPE '\'
			OR LOWER(f.value) LIKE ? ESCAPE '\'
			OR LOWER(f.summary) LIKE ? ESCAPE '\'
			OR LOWER(f.body) LIKE ? ESCAPE '\'
			OR LOWER(f.evidence) LIKE ? ESCAPE '\'
			OR LOWER(f.fact_type) LIKE ? ESCAPE '\'
			OR LOWER(f.memory_kind) LIKE ? ESCAPE '\'
			OR LOWER(f.subject_key) LIKE ? ESCAPE '\'
			OR LOWER(f.predicate) LIKE ? ESCAPE '\'
			OR LOWER(f.object_key) LIKE ? ESCAPE '\'
			OR LOWER(a.name) LIKE ? ESCAPE '\'
			OR LOWER(a.value) LIKE ? ESCAPE '\'
		)`)
		for range 12 {
			args = append(args, pattern)
		}
	}
	whereSQL := strings.Join(where, " AND ")
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM project_facts f
		 LEFT JOIN assets a ON a.id = f.asset_id AND a.project_id = f.project_id
		 WHERE `+whereSQL,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumnsForAlias("f")+`
		 FROM project_facts f
		 LEFT JOIN assets a ON a.id = f.asset_id AND a.project_id = f.project_id
		 WHERE `+whereSQL+`
		 ORDER BY f.updated_at DESC, f.rowid DESC
		 LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ProjectFact, 0, limit)
	for rows.Next() {
		item, scanErr := scanProjectFact(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func projectFactSelectColumnsForAlias(alias string) string {
	columns := []string{
		"id", "project_id", "asset_id", "fact_type", "key", "value", "summary", "body",
		"evidence", "relation", "confidence", "source_type", "source_id", "valid_from",
		"valid_to", "superseded_by", "importance", "version", "embedding",
		"embedding_model", "last_used_at", "use_count", "tainted", "taint_reason",
		"memory_kind", "priority", "pinned", "observed_at", "contradicted_by",
		"conflict_reason", "subject_type", "subject_key", "predicate", "object_type",
		"object_key", "created_at", "updated_at",
	}
	result := make([]string, 0, len(columns))
	for _, column := range columns {
		result = append(result, alias+"."+column)
	}
	return strings.Join(result, ", ")
}
