package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ProjectMemoryEntity struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"projectId"`
	EntityType   string    `json:"entityType"`
	EntityKey    string    `json:"entityKey"`
	Label        string    `json:"label"`
	Summary      string    `json:"summary"`
	Metadata     string    `json:"metadata"`
	SourceRefID  string    `json:"sourceRefId"`
	Evidence     string    `json:"evidence"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	Confidence   int       `json:"confidence"`
	Priority     int       `json:"priority"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidTo      time.Time `json:"validTo"`
	SupersededBy string    `json:"supersededBy"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type ProjectMemoryRelation struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"projectId"`
	SrcEntityID  string    `json:"srcEntityId"`
	Relation     string    `json:"relation"`
	DstEntityID  string    `json:"dstEntityId"`
	FactID       string    `json:"factId"`
	Confidence   int       `json:"confidence"`
	Evidence     string    `json:"evidence"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidTo      time.Time `json:"validTo"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type ProjectFactVersion struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"projectId"`
	FactID     string    `json:"factId"`
	Version    int       `json:"version"`
	Summary    string    `json:"summary"`
	Body       string    `json:"body"`
	Evidence   string    `json:"evidence"`
	Relation   string    `json:"relation"`
	Confidence int       `json:"confidence"`
	MemoryKind string    `json:"memoryKind"`
	Priority   int       `json:"priority"`
	SourceType string    `json:"sourceType"`
	SourceID   string    `json:"sourceId"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"createdAt"`
}

var projectMemoryEntityTypes = map[string]bool{
	"asset": true, "service": true, "endpoint": true, "parameter": true,
	"credential": true, "domain": true, "ip": true, "finding": true,
	"intent": true, "goal": true, "scope": true, "constraint": true,
	"fact": true, "begin": true, "hint": true,
}

var projectMemoryRelationTypes = map[string]bool{
	"contains": true, "exposes": true, "has_parameter": true,
	"authenticated_by": true, "found_on": true, "proves": true,
	"derived_from": true, "plans": true, "aims": true, "depends_on": true,
	"contradicts": true, "supersedes": true, "describes": true,
	"supports": true, "spawns": true, "yields": true, "covers": true,
	"hints": true,
}

const projectMemoryEntityColumns = `id, project_id, entity_type, entity_key, label, summary,
	metadata, source_ref_id, evidence, evidence_refs, confidence, priority,
	valid_from, valid_to, superseded_by, created_at, updated_at`

func scanProjectMemoryEntity(scanner rowScanner) (ProjectMemoryEntity, error) {
	var item ProjectMemoryEntity
	var evidenceRefs string
	var validFrom, validTo, createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.EntityType,
		&item.EntityKey,
		&item.Label,
		&item.Summary,
		&item.Metadata,
		&item.SourceRefID,
		&item.Evidence,
		&evidenceRefs,
		&item.Confidence,
		&item.Priority,
		&validFrom,
		&validTo,
		&item.SupersededBy,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(evidenceRefs)
	item.ValidFrom = unixTimeOrZero(validFrom)
	item.ValidTo = unixTimeOrZero(validTo)
	item.CreatedAt = unixTimeOrZero(createdAt)
	item.UpdatedAt = unixTimeOrZero(updatedAt)
	return item, nil
}

func (db *DB) UpsertProjectMemoryEntity(
	ctx context.Context,
	item ProjectMemoryEntity,
) (*ProjectMemoryEntity, error) {
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.EntityType = strings.ToLower(strings.TrimSpace(item.EntityType))
	item.EntityKey = strings.TrimSpace(item.EntityKey)
	item.Label = strings.TrimSpace(item.Label)
	item.Summary = strings.TrimSpace(item.Summary)
	item.Metadata = strings.TrimSpace(item.Metadata)
	item.SourceRefID = strings.TrimSpace(item.SourceRefID)
	item.Evidence = strings.TrimSpace(item.Evidence)
	item.SupersededBy = strings.TrimSpace(item.SupersededBy)
	if item.ProjectID == "" || item.EntityKey == "" || !projectMemoryEntityTypes[item.EntityType] {
		return nil, fmt.Errorf("记忆实体参数不合法")
	}
	if item.Metadata == "" {
		item.Metadata = "{}"
	}
	if item.Confidence < 0 {
		item.Confidence = 0
	}
	if item.Confidence > 100 {
		item.Confidence = 100
	}
	if item.Priority <= 0 {
		item.Priority = 50
	}
	if item.Priority > 100 {
		item.Priority = 100
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	if item.ValidFrom.IsZero() {
		item.ValidFrom = now
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	evidenceRefs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO project_memory_entities (
			id, project_id, entity_type, entity_key, label, summary, metadata,
			source_ref_id, evidence, evidence_refs, confidence, priority,
			valid_from, valid_to, superseded_by, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, entity_type, entity_key) DO UPDATE SET
			label = CASE WHEN excluded.label <> '' THEN excluded.label ELSE project_memory_entities.label END,
			summary = CASE WHEN excluded.summary <> '' THEN excluded.summary ELSE project_memory_entities.summary END,
			metadata = CASE WHEN excluded.metadata <> '{}' THEN excluded.metadata ELSE project_memory_entities.metadata END,
			source_ref_id = CASE WHEN excluded.source_ref_id <> '' THEN excluded.source_ref_id ELSE project_memory_entities.source_ref_id END,
			evidence = CASE WHEN excluded.evidence <> '' THEN excluded.evidence ELSE project_memory_entities.evidence END,
			evidence_refs = CASE WHEN excluded.evidence_refs <> '[]' THEN excluded.evidence_refs ELSE project_memory_entities.evidence_refs END,
			confidence = CASE WHEN excluded.confidence > project_memory_entities.confidence THEN excluded.confidence ELSE project_memory_entities.confidence END,
			priority = CASE WHEN excluded.priority > project_memory_entities.priority THEN excluded.priority ELSE project_memory_entities.priority END,
			valid_to = CASE
				WHEN excluded.valid_to > 0 THEN excluded.valid_to
				ELSE project_memory_entities.valid_to
			END,
			superseded_by = CASE
				WHEN excluded.superseded_by <> '' THEN excluded.superseded_by
				ELSE project_memory_entities.superseded_by
			END,
			updated_at = excluded.updated_at`,
		item.ID,
		item.ProjectID,
		item.EntityType,
		item.EntityKey,
		item.Label,
		item.Summary,
		item.Metadata,
		item.SourceRefID,
		item.Evidence,
		evidenceRefs,
		item.Confidence,
		item.Priority,
		item.ValidFrom.Unix(),
		item.ValidTo.Unix(),
		item.SupersededBy,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	return db.GetProjectMemoryEntity(ctx, item.ProjectID, item.EntityType, item.EntityKey)
}

func (db *DB) GetProjectMemoryEntity(
	ctx context.Context,
	projectID string,
	entityType string,
	entityKey string,
) (*ProjectMemoryEntity, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectMemoryEntityColumns+`
		 FROM project_memory_entities
		 WHERE project_id = ? AND entity_type = ? AND entity_key = ?`,
		strings.TrimSpace(projectID),
		strings.ToLower(strings.TrimSpace(entityType)),
		strings.TrimSpace(entityKey),
	)
	item, err := scanProjectMemoryEntity(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListProjectMemoryEntities(
	ctx context.Context,
	projectID string,
	entityType string,
	limit int,
) ([]ProjectMemoryEntity, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + projectMemoryEntityColumns + `
		FROM project_memory_entities WHERE project_id = ?`
	args := []interface{}{strings.TrimSpace(projectID)}
	if entityType = strings.ToLower(strings.TrimSpace(entityType)); entityType != "" {
		query += ` AND entity_type = ?`
		args = append(args, entityType)
	}
	query += ` ORDER BY priority DESC, updated_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectMemoryEntity, 0)
	for rows.Next() {
		item, scanErr := scanProjectMemoryEntity(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

const projectMemoryRelationColumns = `id, project_id, src_entity_id, relation, dst_entity_id,
	fact_id, confidence, evidence, evidence_refs, valid_from, valid_to, created_at, updated_at`

func scanProjectMemoryRelation(scanner rowScanner) (ProjectMemoryRelation, error) {
	var item ProjectMemoryRelation
	var evidenceRefs string
	var validFrom, validTo, createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.SrcEntityID,
		&item.Relation,
		&item.DstEntityID,
		&item.FactID,
		&item.Confidence,
		&item.Evidence,
		&evidenceRefs,
		&validFrom,
		&validTo,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(evidenceRefs)
	item.ValidFrom = unixTimeOrZero(validFrom)
	item.ValidTo = unixTimeOrZero(validTo)
	item.CreatedAt = unixTimeOrZero(createdAt)
	item.UpdatedAt = unixTimeOrZero(updatedAt)
	return item, nil
}

func (db *DB) UpsertProjectMemoryRelation(
	ctx context.Context,
	item ProjectMemoryRelation,
) (*ProjectMemoryRelation, error) {
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.SrcEntityID = strings.TrimSpace(item.SrcEntityID)
	item.DstEntityID = strings.TrimSpace(item.DstEntityID)
	item.Relation = strings.ToLower(strings.TrimSpace(item.Relation))
	item.FactID = strings.TrimSpace(item.FactID)
	item.Evidence = strings.TrimSpace(item.Evidence)
	if item.ProjectID == "" || item.SrcEntityID == "" || item.DstEntityID == "" ||
		item.SrcEntityID == item.DstEntityID || !projectMemoryRelationTypes[item.Relation] {
		return nil, fmt.Errorf("记忆关系参数不合法")
	}
	if _, err := db.GetProjectMemoryEntityByID(ctx, item.ProjectID, item.SrcEntityID); err != nil {
		return nil, fmt.Errorf("源实体不存在")
	}
	if _, err := db.GetProjectMemoryEntityByID(ctx, item.ProjectID, item.DstEntityID); err != nil {
		return nil, fmt.Errorf("目标实体不存在")
	}
	if item.Confidence < 0 {
		item.Confidence = 0
	}
	if item.Confidence > 100 {
		item.Confidence = 100
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	if item.ValidFrom.IsZero() {
		item.ValidFrom = now
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	evidenceRefs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO project_memory_relations (
			id, project_id, src_entity_id, relation, dst_entity_id, fact_id,
			confidence, evidence, evidence_refs, valid_from, valid_to, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, src_entity_id, relation, dst_entity_id) DO UPDATE SET
			fact_id = CASE WHEN excluded.fact_id <> '' THEN excluded.fact_id ELSE project_memory_relations.fact_id END,
			confidence = CASE WHEN excluded.confidence > project_memory_relations.confidence THEN excluded.confidence ELSE project_memory_relations.confidence END,
			evidence = CASE WHEN excluded.evidence <> '' THEN excluded.evidence ELSE project_memory_relations.evidence END,
			evidence_refs = CASE WHEN excluded.evidence_refs <> '[]' THEN excluded.evidence_refs ELSE project_memory_relations.evidence_refs END,
			valid_to = CASE
				WHEN excluded.valid_to > 0 THEN excluded.valid_to
				ELSE project_memory_relations.valid_to
			END,
			updated_at = excluded.updated_at`,
		item.ID,
		item.ProjectID,
		item.SrcEntityID,
		item.Relation,
		item.DstEntityID,
		item.FactID,
		item.Confidence,
		item.Evidence,
		evidenceRefs,
		item.ValidFrom.Unix(),
		item.ValidTo.Unix(),
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	return db.GetProjectMemoryRelation(ctx, item.ProjectID, item.SrcEntityID, item.Relation, item.DstEntityID)
}

func (db *DB) GetProjectMemoryEntityByID(
	ctx context.Context,
	projectID string,
	id string,
) (*ProjectMemoryEntity, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectMemoryEntityColumns+`
		 FROM project_memory_entities WHERE project_id = ? AND id = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(id),
	)
	item, err := scanProjectMemoryEntity(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) GetProjectMemoryRelation(
	ctx context.Context,
	projectID string,
	srcID string,
	relation string,
	dstID string,
) (*ProjectMemoryRelation, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectMemoryRelationColumns+`
		 FROM project_memory_relations
		 WHERE project_id = ? AND src_entity_id = ? AND relation = ? AND dst_entity_id = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(srcID),
		strings.ToLower(strings.TrimSpace(relation)),
		strings.TrimSpace(dstID),
	)
	item, err := scanProjectMemoryRelation(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListProjectMemoryRelations(
	ctx context.Context,
	projectID string,
	entityID string,
	limit int,
) ([]ProjectMemoryRelation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT ` + projectMemoryRelationColumns + `
		FROM project_memory_relations WHERE project_id = ?`
	args := []interface{}{strings.TrimSpace(projectID)}
	if entityID = strings.TrimSpace(entityID); entityID != "" {
		query += ` AND (src_entity_id = ? OR dst_entity_id = ?)`
		args = append(args, entityID, entityID)
	}
	query += ` ORDER BY updated_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectMemoryRelation, 0)
	for rows.Next() {
		item, scanErr := scanProjectMemoryRelation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) RecordProjectFactVersion(
	ctx context.Context,
	fact ProjectFact,
	reason string,
) error {
	if strings.TrimSpace(fact.ID) == "" || strings.TrimSpace(fact.ProjectID) == "" {
		return fmt.Errorf("事实版本参数不合法")
	}
	if fact.Version <= 0 {
		fact.Version = 1
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO project_fact_versions (
			id, project_id, fact_id, version, summary, body, evidence, relation,
			confidence, memory_kind, priority, source_type, source_id, reason, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID(),
		fact.ProjectID,
		fact.ID,
		fact.Version,
		fact.Summary,
		fact.Body,
		fact.Evidence,
		fact.Relation,
		fact.Confidence,
		fact.MemoryKind,
		fact.Priority,
		fact.SourceType,
		fact.SourceID,
		strings.TrimSpace(reason),
		time.Now().UTC().Unix(),
	)
	return err
}

func (db *DB) ListProjectFactVersions(
	ctx context.Context,
	projectID string,
	factID string,
	limit int,
) ([]ProjectFactVersion, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, fact_id, version, summary, body, evidence, relation,
			confidence, memory_kind, priority, source_type, source_id, reason, created_at
		 FROM project_fact_versions
		 WHERE project_id = ? AND fact_id = ?
		 ORDER BY version DESC, created_at DESC LIMIT ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(factID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectFactVersion, 0)
	for rows.Next() {
		var item ProjectFactVersion
		var createdAt int64
		if err := rows.Scan(
			&item.ID, &item.ProjectID, &item.FactID, &item.Version,
			&item.Summary, &item.Body, &item.Evidence, &item.Relation,
			&item.Confidence, &item.MemoryKind, &item.Priority,
			&item.SourceType, &item.SourceID, &item.Reason, &createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetProjectFactByID(
	ctx context.Context,
	projectID string,
	id string,
) (*ProjectFact, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts WHERE project_id = ? AND id = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(id),
	)
	item, err := scanProjectFact(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) GetActiveProjectFactByID(
	ctx context.Context,
	projectID string,
	id string,
) (*ProjectFact, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND id = ?
		   AND valid_to = 0 AND superseded_by = ''`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(id),
	)
	item, err := scanProjectFact(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) MarkProjectFactConflict(
	ctx context.Context,
	projectID string,
	leftFactID string,
	rightFactID string,
	reason string,
) error {
	now := time.Now().UTC().Unix()
	for _, pair := range [][2]string{{leftFactID, rightFactID}, {rightFactID, leftFactID}} {
		result, err := db.ExecContext(
			ctx,
			`UPDATE project_facts
			 SET contradicted_by = ?, conflict_reason = ?, updated_at = ?
			 WHERE id = ? AND project_id = ?`,
			pair[1],
			strings.TrimSpace(reason),
			now,
			pair[0],
			strings.TrimSpace(projectID),
		)
		if err != nil {
			return err
		}
		if err := requireAffected(result, nil); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) ListProjectFactConflicts(
	ctx context.Context,
	projectID string,
	limit int,
) ([]ProjectFact, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND TRIM(contradicted_by) <> '' AND valid_to = 0
		 ORDER BY priority DESC, updated_at DESC LIMIT ?`,
		strings.TrimSpace(projectID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectFact, 0)
	for rows.Next() {
		item, scanErr := scanProjectFact(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ResolveProjectFactConflict(
	ctx context.Context,
	projectID string,
	winnerID string,
	loserID string,
	reason string,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	var loserContradictedBy string
	var winnerContradictedBy string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT contradicted_by FROM project_facts WHERE id = ? AND project_id = ? AND valid_to = 0`,
		loserID,
		projectID,
	).Scan(&loserContradictedBy); err != nil {
		return err
	}
	if err := tx.QueryRowContext(
		ctx,
		`SELECT contradicted_by FROM project_facts WHERE id = ? AND project_id = ? AND valid_to = 0`,
		winnerID,
		projectID,
	).Scan(&winnerContradictedBy); err != nil {
		return err
	}
	if loserContradictedBy != winnerID && winnerContradictedBy != loserID {
		return fmt.Errorf("winner 与 loser 不属于同一冲突组")
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET valid_to = ?, superseded_by = ?, contradicted_by = '', conflict_reason = '', updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		now.Unix(),
		winnerID,
		now.Unix(),
		loserID,
		projectID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET contradicted_by = '', conflict_reason = ?, updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		strings.TrimSpace(reason),
		now.Unix(),
		winnerID,
		projectID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) SyncProjectMemory(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) error {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return fmt.Errorf("项目和用户不能为空")
	}
	if _, err := db.GetProject(ctx, projectID, ownerUserID); err != nil {
		return err
	}
	entityByRef := map[string]*ProjectMemoryEntity{}
	assets, err := db.ListProjectAssets(ctx, projectID, ownerUserID)
	if err != nil {
		return err
	}
	for _, asset := range assets {
		entity, err := db.UpsertProjectMemoryEntity(ctx, ProjectMemoryEntity{
			ProjectID:   projectID,
			EntityType:  "asset",
			EntityKey:   asset.ID,
			Label:       asset.Name,
			Summary:     asset.Value,
			SourceRefID: asset.ID,
			Confidence:  90,
			Priority:    coverageCriticalityWeight(asset.Criticality),
		})
		if err != nil {
			return err
		}
		entityByRef["asset:"+asset.ID] = entity
	}
	findings, _, err := db.ListVulnerabilitiesFiltered(ctx, VulnerabilityFilter{
		OwnerUserID: ownerUserID,
		ProjectID:   projectID,
		Limit:       1000,
	})
	if err != nil {
		return err
	}
	for _, finding := range findings {
		entity, err := db.UpsertProjectMemoryEntity(ctx, ProjectMemoryEntity{
			ProjectID:    projectID,
			EntityType:   "finding",
			EntityKey:    finding.ID,
			Label:        finding.Title,
			Summary:      finding.Description,
			SourceRefID:  finding.ID,
			Evidence:     finding.Evidence,
			EvidenceRefs: finding.EvidenceRefs,
			Confidence:   finding.Confidence,
			Priority:     coverageSeverityWeight(finding.Severity) * 2,
		})
		if err != nil {
			return err
		}
		entityByRef["finding:"+finding.ID] = entity
		if src := entityByRef["finding:"+finding.ID]; src != nil {
			if dst := entityByRef["asset:"+finding.AssetID]; dst != nil {
				if _, err := db.UpsertProjectMemoryRelation(ctx, ProjectMemoryRelation{
					ProjectID:   projectID,
					SrcEntityID: src.ID,
					Relation:    "found_on",
					DstEntityID: dst.ID,
					Confidence:  finding.Confidence,
					Evidence:    finding.Evidence,
				}); err != nil {
					return err
				}
			}
		}
	}
	nodes, err := db.ListProjectGraphNodes(ctx, projectID)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		entityType := strings.ToLower(strings.TrimSpace(node.Kind))
		if !projectMemoryEntityTypes[entityType] {
			entityType = "fact"
		}
		entity, err := db.UpsertProjectMemoryEntity(ctx, ProjectMemoryEntity{
			ProjectID:   projectID,
			EntityType:  entityType,
			EntityKey:   node.ID,
			Label:       node.Title,
			Summary:     node.Detail,
			SourceRefID: node.SourceRefID,
			Confidence:  node.Confidence,
			Priority:    node.Confidence,
		})
		if err != nil {
			return err
		}
		entityByRef["node:"+node.ID] = entity
	}
	edges, err := db.ListProjectGraphEdges(ctx, projectID)
	if err != nil {
		return err
	}
	for _, edge := range edges {
		src := entityByRef["node:"+edge.SrcID]
		dst := entityByRef["node:"+edge.DstID]
		if src == nil || dst == nil {
			continue
		}
		relation := strings.ToLower(strings.TrimSpace(edge.Rel))
		if !projectMemoryRelationTypes[relation] {
			relation = "depends_on"
		}
		if _, err := db.UpsertProjectMemoryRelation(ctx, ProjectMemoryRelation{
			ProjectID:   projectID,
			SrcEntityID: src.ID,
			Relation:    relation,
			DstEntityID: dst.ID,
			Confidence:  80,
		}); err != nil {
			return err
		}
	}
	facts, err := db.ListProjectFacts(ctx, projectID)
	if err != nil {
		return err
	}
	for _, fact := range facts {
		entityType := "fact"
		switch strings.ToLower(strings.TrimSpace(fact.MemoryKind)) {
		case "credential":
			entityType = "credential"
		case "scope":
			entityType = "scope"
		case "constraint":
			entityType = "constraint"
		}
		entity, err := db.UpsertProjectMemoryEntity(ctx, ProjectMemoryEntity{
			ProjectID:   projectID,
			EntityType:  entityType,
			EntityKey:   fact.Key,
			Label:       fact.Key,
			Summary:     projectMemoryFactSummary(fact),
			SourceRefID: fact.ID,
			Evidence:    fact.Evidence,
			Confidence:  fact.Confidence,
			Priority:    fact.Priority,
		})
		if err != nil {
			return err
		}
		entityByRef["fact:"+fact.Key] = entity
		for _, ref := range splitProjectFactRelationRefs(fact.Relation) {
			dst := entityByRef[ref]
			if dst == nil || dst.ID == entity.ID {
				continue
			}
			relation := "describes"
			if strings.HasPrefix(ref, "finding:") {
				relation = "supports"
			} else if strings.HasPrefix(ref, "fact:") {
				relation = "derived_from"
			}
			if _, err := db.UpsertProjectMemoryRelation(ctx, ProjectMemoryRelation{
				ProjectID:   projectID,
				SrcEntityID: entity.ID,
				Relation:    relation,
				DstEntityID: dst.ID,
				FactID:      fact.ID,
				Confidence:  fact.Confidence,
				Evidence:    fact.Evidence,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func splitProjectFactRelationRefs(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', ';', ' ', '\t', '\n', '，', '；':
			return true
		default:
			return false
		}
	})
}

func projectMemoryFactSummary(fact ProjectFact) string {
	if summary := strings.TrimSpace(fact.Summary); summary != "" {
		return summary
	}
	return strings.TrimSpace(fact.Value)
}
