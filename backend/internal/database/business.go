package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var ErrProjectInactive = errors.New("项目当前状态不允许执行 Agent 工作")

const assetDeleteIDBatchSize = 400

type AssetDeleteImpact struct {
	AssetID          string `json:"assetId"`
	ProjectID        string `json:"projectId"`
	AssetName        string `json:"assetName"`
	AssetValue       string `json:"assetValue"`
	Intents          int64  `json:"intents"`
	Facts            int64  `json:"facts"`
	MemoryEntities   int64  `json:"memoryEntities"`
	Findings         int64  `json:"findings"`
	Tests            int64  `json:"tests"`
	GraphNodes       int64  `json:"graphNodes"`
	CampaignRecords  int64  `json:"campaignRecords"`
	Conversations    int64  `json:"conversations"`
	VulnerabilityFPs int64  `json:"vulnerabilityFingerprints"`
}

type Project struct {
	ID          string    `json:"id"`
	OwnerUserID string    `json:"ownerUserId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Goals       string    `json:"goals"`
	Constraints string    `json:"constraints,omitempty"`
	Scope       string    `json:"scope"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type ProjectFact struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"projectId"`
	AssetID        string    `json:"assetId"`
	FactType       string    `json:"factType"`
	Key            string    `json:"key"`
	Value          string    `json:"value"`
	Summary        string    `json:"summary"`
	Body           string    `json:"body"`
	Evidence       string    `json:"evidence"`
	Relation       string    `json:"relation"`
	Confidence     int       `json:"confidence"`
	SourceType     string    `json:"sourceType"`
	SourceID       string    `json:"sourceId"`
	ValidFrom      time.Time `json:"validFrom"`
	ValidTo        time.Time `json:"validTo"`
	SupersededBy   string    `json:"supersededBy"`
	Importance     int       `json:"importance"`
	Version        int       `json:"version"`
	Embedding      []byte    `json:"-"`
	EmbeddingModel string    `json:"embeddingModel"`
	LastUsedAt     time.Time `json:"lastUsedAt"`
	UseCount       int       `json:"useCount"`
	Tainted        bool      `json:"tainted"`
	TaintReason    string    `json:"taintReason"`
	MemoryKind     string    `json:"memoryKind"`
	Priority       int       `json:"priority"`
	Pinned         bool      `json:"pinned"`
	ObservedAt     time.Time `json:"observedAt"`
	ContradictedBy string    `json:"contradictedBy"`
	ConflictReason string    `json:"conflictReason"`
	SubjectType    string    `json:"subjectType"`
	SubjectKey     string    `json:"subjectKey"`
	Predicate      string    `json:"predicate"`
	ObjectType     string    `json:"objectType"`
	ObjectKey      string    `json:"objectKey"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Asset struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"projectId"`
	OwnerUserID     string    `json:"ownerUserId"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Value           string    `json:"value"`
	NormalizedValue string    `json:"normalizedValue,omitempty"`
	QualityStatus   string    `json:"qualityStatus,omitempty"`
	Status          string    `json:"status"`
	Source          string    `json:"source"`
	Criticality     string    `json:"criticality"`
	RiskScore       int       `json:"riskScore"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type Vulnerability struct {
	ID                string    `json:"id"`
	ProjectID         string    `json:"projectId"`
	AssetID           string    `json:"assetId"`
	OwnerUserID       string    `json:"ownerUserId"`
	Title             string    `json:"title"`
	Severity          string    `json:"severity"`
	Status            string    `json:"status"`
	VulnerabilityType string    `json:"vulnerabilityType"`
	Target            string    `json:"target"`
	Parameter         string    `json:"parameter"`
	HTTPMethod        string    `json:"httpMethod"`
	Preconditions     string    `json:"preconditions"`
	ReproductionSteps string    `json:"reproductionSteps"`
	Description       string    `json:"description"`
	Evidence          string    `json:"evidence"`
	EvidenceRefs      []string  `json:"evidenceRefs"`
	Impact            string    `json:"impact"`
	Recommendation    string    `json:"recommendation"`
	RetestNotes       string    `json:"retestNotes"`
	Fingerprint       string    `json:"fingerprint"`
	VerificationState string    `json:"verificationState"`
	Confidence        int       `json:"confidence"`
	Exploitability    string    `json:"exploitability"`
	TestTechnique     string    `json:"testTechnique"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type KnowledgeItem struct {
	ID          string    `json:"id"`
	OwnerUserID string    `json:"ownerUserId"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type WebShellConnection struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	OwnerUserID string    `json:"ownerUserId"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	Password    string    `json:"-"`
	Encoding    string    `json:"encoding"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (db *DB) CreateProject(ctx context.Context, item Project) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO projects (
			id, owner_user_id, name, description, goals, scope, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.OwnerUserID,
		item.Name,
		item.Description,
		item.Goals,
		item.Scope,
		item.Status,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) ListProjects(ctx context.Context, ownerUserID string) ([]Project, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, name, description, goals, scope, status, created_at, updated_at
		 FROM projects
		 WHERE owner_user_id = ?
		 ORDER BY updated_at DESC`,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Project, 0)
	for rows.Next() {
		var item Project
		var createdAt int64
		var updatedAt int64
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
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		item.Constraints = ProjectConstraintsText(item.Goals)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetProject(ctx context.Context, id, ownerUserID string) (*Project, error) {
	var item Project
	var createdAt int64
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, owner_user_id, name, description, goals, scope, status, created_at, updated_at
		 FROM projects
		 WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.Name,
		&item.Description,
		&item.Goals,
		&item.Scope,
		&item.Status,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	item.Constraints = ProjectConstraintsText(item.Goals)
	return &item, nil
}

func (db *DB) GetActiveProject(
	ctx context.Context,
	id string,
	ownerUserID string,
) (*Project, error) {
	project, err := db.GetProject(ctx, id, ownerUserID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(project.Status), "active") {
		return nil, fmt.Errorf("%w: 当前状态 %s", ErrProjectInactive, project.Status)
	}
	return project, nil
}

func (db *DB) UpdateProject(ctx context.Context, item Project) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE projects
		 SET name = ?, description = ?, goals = ?, scope = ?, status = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		item.Name,
		item.Description,
		item.Goals,
		item.Scope,
		item.Status,
		item.UpdatedAt.Unix(),
		item.ID,
		item.OwnerUserID,
	)
	return requireAffected(result, err)
}

func (db *DB) DeleteProject(ctx context.Context, id, ownerUserID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM projects WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}

	// 关联对话：messages / process_details / conversation_summaries 由外键 ON DELETE CASCADE 处理，
	// token_usage / hitl_requests / tool_executions 没有外键，需要显式清理（与删除单条对话一致）。
	conversationIDs := make([]string, 0)
	rows, err := tx.QueryContext(
		ctx,
		`SELECT id FROM conversations WHERE project_id = ?`,
		id,
	)
	if err != nil {
		return err
	}
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			_ = rows.Close()
			return err
		}
		conversationIDs = append(conversationIDs, conversationID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, conversationID := range conversationIDs {
		for _, statement := range []string{
			`DELETE FROM token_usage WHERE conversation_id = ?`,
			`DELETE FROM hitl_requests WHERE conversation_id = ?`,
			`DELETE FROM tool_executions WHERE conversation_id = ?`,
			`DELETE FROM tool_jobs WHERE conversation_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, statement, conversationID); err != nil {
				return err
			}
		}
	}

	// 项目内的对话、资产、漏洞、WebShell 连接、事实、攻击步骤与攻击路径图。
	for _, statement := range []string{
		`DELETE FROM campaign_chain_steps WHERE chain_id IN (
			SELECT id FROM campaign_chains WHERE campaign_id IN (
				SELECT id FROM conversation_batches WHERE project_id = ?
			)
		 )`,
		`DELETE FROM campaign_chains WHERE project_id = ?`,
		`DELETE FROM campaign_memory_digests WHERE project_id = ?`,
		`DELETE FROM campaign_verifications WHERE campaign_id IN (
			SELECT id FROM conversation_batches WHERE project_id = ?
		 )`,
		`DELETE FROM campaign_links WHERE project_id = ?`,
		`DELETE FROM campaign_frontier WHERE campaign_id IN (
			SELECT id FROM conversation_batches WHERE project_id = ?
		 )`,
		`DELETE FROM campaign_coverage WHERE campaign_id IN (
			SELECT id FROM conversation_batches WHERE project_id = ?
		 )`,
		`DELETE FROM campaign_tasks WHERE project_id = ?`,
		`DELETE FROM campaign_endpoints WHERE project_id = ?`,
		`DELETE FROM campaign_groups WHERE project_id = ?`,
		`DELETE FROM conversation_batches WHERE project_id = ?`,
		`DELETE FROM conversations WHERE project_id = ?`,
		`DELETE FROM vulnerabilities WHERE project_id = ?`,
		`DELETE FROM project_asset_work WHERE project_id = ?`,
		`DELETE FROM assets WHERE project_id = ?`,
		`DELETE FROM webshell_connections WHERE project_id = ?`,
		`DELETE FROM project_facts WHERE project_id = ?`,
		`DELETE FROM project_test_results WHERE project_id = ?`,
		`DELETE FROM vulnerability_fingerprints WHERE project_id = ?`,
		`DELETE FROM project_attack_steps WHERE project_id = ?`,
		`DELETE FROM project_graph_edges WHERE project_id = ?`,
		`DELETE FROM project_graph_nodes WHERE project_id = ?`,
		`DELETE FROM vulnerability_report_drafts WHERE project_id = ?`,
		`DELETE FROM tool_registry WHERE project_id = ?`,
		`DELETE FROM tool_runtime_paths WHERE project_id = ?`,
		`DELETE FROM intel_searches WHERE project_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) UpsertProjectFact(ctx context.Context, item ProjectFact) (*ProjectFact, error) {
	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.AssetID = strings.TrimSpace(item.AssetID)
	item.Summary = strings.TrimSpace(item.Summary)
	item.Value = strings.TrimSpace(item.Value)
	if item.Summary == "" {
		item.Summary = item.Value
	}
	item.Value = item.Summary
	item.UpdatedAt = now
	if item.ValidFrom.IsZero() {
		item.ValidFrom = now
	}
	if item.Importance <= 0 {
		item.Importance = 50
	}
	if item.Importance > 100 {
		item.Importance = 100
	}
	if item.Version <= 0 {
		item.Version = 1
	}
	item.MemoryKind = strings.TrimSpace(item.MemoryKind)
	if item.MemoryKind == "" {
		item.MemoryKind = "general"
	}
	if item.Priority <= 0 {
		item.Priority = item.Importance
	}
	if item.Priority < 0 {
		item.Priority = 0
	}
	if item.Priority > 100 {
		item.Priority = 100
	}
	if item.ObservedAt.IsZero() {
		item.ObservedAt = now
	}
	item.SubjectType = strings.TrimSpace(item.SubjectType)
	item.SubjectKey = strings.TrimSpace(item.SubjectKey)
	item.Predicate = strings.TrimSpace(item.Predicate)
	item.ObjectType = strings.TrimSpace(item.ObjectType)
	item.ObjectKey = strings.TrimSpace(item.ObjectKey)
	var storedID string
	var storedCreatedAt int64
	var storedValidFrom int64
	err := db.QueryRowContext(
		ctx,
		`INSERT INTO project_facts (
			id, project_id, asset_id, fact_type, key, value, summary, body, evidence, relation,
			confidence, source_type, source_id, valid_from,
			importance, version, embedding_model, tainted, taint_reason,
			memory_kind, priority, pinned, observed_at, contradicted_by, conflict_reason,
			subject_type, subject_key, predicate, object_type, object_key,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, asset_id, key) DO UPDATE SET
			fact_type = excluded.fact_type,
			value = excluded.value,
			summary = excluded.summary,
			body = CASE WHEN excluded.body = '' THEN project_facts.body ELSE excluded.body END,
			evidence = CASE WHEN excluded.evidence = '' THEN project_facts.evidence ELSE excluded.evidence END,
			relation = CASE WHEN excluded.relation = '' THEN project_facts.relation ELSE excluded.relation END,
			confidence = excluded.confidence,
			source_type = excluded.source_type,
			source_id = excluded.source_id,
			valid_from = excluded.valid_from,
			valid_to = 0,
			superseded_by = '',
			importance = excluded.importance,
			version = project_facts.version + 1,
			embedding = CASE WHEN project_facts.summary = excluded.summary THEN project_facts.embedding ELSE NULL END,
			embedding_model = CASE WHEN project_facts.summary = excluded.summary THEN project_facts.embedding_model ELSE '' END,
			tainted = excluded.tainted,
			taint_reason = excluded.taint_reason,
			memory_kind = excluded.memory_kind,
			priority = excluded.priority,
			pinned = CASE
				WHEN excluded.pinned = 1 THEN 1
				ELSE project_facts.pinned
			END,
			observed_at = CASE
				WHEN excluded.observed_at > 0 THEN excluded.observed_at
				ELSE project_facts.observed_at
			END,
			contradicted_by = excluded.contradicted_by,
			conflict_reason = excluded.conflict_reason,
			subject_type = excluded.subject_type,
			subject_key = excluded.subject_key,
			predicate = excluded.predicate,
			object_type = excluded.object_type,
			object_key = excluded.object_key,
			updated_at = excluded.updated_at
		RETURNING id, created_at, valid_from, version`,
		item.ID,
		item.ProjectID,
		item.AssetID,
		item.FactType,
		item.Key,
		item.Value,
		item.Summary,
		item.Body,
		item.Evidence,
		item.Relation,
		item.Confidence,
		item.SourceType,
		item.SourceID,
		item.ValidFrom.Unix(),
		item.Importance,
		item.Version,
		item.EmbeddingModel,
		boolToInt(item.Tainted),
		item.TaintReason,
		item.MemoryKind,
		item.Priority,
		boolToInt(item.Pinned),
		item.ObservedAt.Unix(),
		item.ContradictedBy,
		item.ConflictReason,
		item.SubjectType,
		item.SubjectKey,
		item.Predicate,
		item.ObjectType,
		item.ObjectKey,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	).Scan(&storedID, &storedCreatedAt, &storedValidFrom, &item.Version)
	if err != nil {
		return nil, err
	}
	item.ID = storedID
	item.CreatedAt = time.Unix(storedCreatedAt, 0)
	item.ValidFrom = time.Unix(storedValidFrom, 0)
	return &item, nil
}

const projectFactSelectColumns = `id, project_id, asset_id, fact_type, key, value, summary, body, evidence, relation,
	confidence, source_type, source_id, valid_from, valid_to, superseded_by,
	importance, version, embedding, embedding_model, last_used_at, use_count,
	tainted, taint_reason, memory_kind, priority, pinned, observed_at,
	contradicted_by, conflict_reason, subject_type, subject_key, predicate,
	object_type, object_key, created_at, updated_at`

type projectFactScanner interface {
	Scan(dest ...interface{}) error
}

func scanProjectFact(row projectFactScanner) (ProjectFact, error) {
	var item ProjectFact
	var validFrom, validTo, lastUsedAt, observedAt, createdAt, updatedAt int64
	if err := row.Scan(
		&item.ID,
		&item.ProjectID,
		&item.AssetID,
		&item.FactType,
		&item.Key,
		&item.Value,
		&item.Summary,
		&item.Body,
		&item.Evidence,
		&item.Relation,
		&item.Confidence,
		&item.SourceType,
		&item.SourceID,
		&validFrom,
		&validTo,
		&item.SupersededBy,
		&item.Importance,
		&item.Version,
		&item.Embedding,
		&item.EmbeddingModel,
		&lastUsedAt,
		&item.UseCount,
		&item.Tainted,
		&item.TaintReason,
		&item.MemoryKind,
		&item.Priority,
		&item.Pinned,
		&observedAt,
		&item.ContradictedBy,
		&item.ConflictReason,
		&item.SubjectType,
		&item.SubjectKey,
		&item.Predicate,
		&item.ObjectType,
		&item.ObjectKey,
		&createdAt,
		&updatedAt,
	); err != nil {
		return ProjectFact{}, err
	}
	item.ValidFrom = unixTimeOrZero(validFrom)
	item.ValidTo = unixTimeOrZero(validTo)
	item.LastUsedAt = unixTimeOrZero(lastUsedAt)
	item.ObservedAt = unixTimeOrZero(observedAt)
	item.CreatedAt = unixTimeOrZero(createdAt)
	item.UpdatedAt = unixTimeOrZero(updatedAt)
	return item, nil
}

func (db *DB) GetProjectFactByKey(
	ctx context.Context,
	projectID string,
	assetID string,
	key string,
) (*ProjectFact, error) {
	assetID = strings.TrimSpace(assetID)
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND asset_id = ? AND key = ?`,
		projectID,
		assetID,
		key,
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

// TouchProjectFact 记录记忆被召回使用，供重要度/衰减排序参考。
func (db *DB) TouchProjectFact(ctx context.Context, factID string) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET last_used_at = ?, use_count = use_count + 1
		 WHERE id = ?`,
		time.Now().UTC().Unix(),
		factID,
	)
	return err
}

// SupersedeProjectFact 标记旧记忆失效（valid_to），supersededBy 指向替代记忆。
func (db *DB) SupersedeProjectFact(ctx context.Context, factID, supersededBy string) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET valid_to = ?, superseded_by = ?, updated_at = ?
		 WHERE id = ?`,
		time.Now().UTC().Unix(),
		supersededBy,
		time.Now().UTC().Unix(),
		factID,
	)
	return err
}

func (db *DB) ListProjectFactEmbeddingCandidates(
	ctx context.Context,
	projectID string,
	limit int,
) ([]ProjectFact, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND valid_to = 0 AND embedding IS NULL
		 ORDER BY updated_at DESC
		 LIMIT ?`,
		projectID,
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

func (db *DB) UpdateProjectFactEmbedding(
	ctx context.Context,
	factID string,
	model string,
	embedding []byte,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET embedding = ?, embedding_model = ?
		 WHERE id = ?`,
		embedding,
		model,
		factID,
	)
	return err
}

// MemoryWrite 记录一次记忆写决策（ADD/UPDATE/NONE/SUPERSEDE），用于审计误合并。
type MemoryWrite struct {
	ID            string
	ProjectID     string
	FactID        string
	Action        string
	Reason        string
	BeforeKey     string
	AfterKey      string
	RelatedFactID string
	BeforeSummary string
	AfterSummary  string
	SourceType    string
	SourceID      string
	Similarity    float64
	CreatedAt     time.Time
}

func (db *DB) AddMemoryWrite(ctx context.Context, item MemoryWrite) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO memory_writes (
			id, project_id, fact_id, action, reason, before_key, after_key, related_fact_id,
			before_summary, after_summary, source_type, source_id, similarity, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ProjectID,
		item.FactID,
		item.Action,
		item.Reason,
		item.BeforeKey,
		item.AfterKey,
		item.RelatedFactID,
		item.BeforeSummary,
		item.AfterSummary,
		item.SourceType,
		item.SourceID,
		item.Similarity,
		item.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) ListMemoryWrites(
	ctx context.Context,
	projectID string,
	limit int,
) ([]MemoryWrite, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, fact_id, action, reason, before_key, after_key, related_fact_id,
		        before_summary, after_summary, source_type, source_id, similarity, created_at
		 FROM memory_writes
		 WHERE project_id = ?
		 ORDER BY created_at DESC
		 LIMIT ?`,
		projectID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]MemoryWrite, 0)
	for rows.Next() {
		var item MemoryWrite
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.FactID,
			&item.Action,
			&item.Reason,
			&item.BeforeKey,
			&item.AfterKey,
			&item.RelatedFactID,
			&item.BeforeSummary,
			&item.AfterSummary,
			&item.SourceType,
			&item.SourceID,
			&item.Similarity,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListProjectFacts(ctx context.Context, projectID string) ([]ProjectFact, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND valid_to = 0
		 ORDER BY updated_at DESC`,
		projectID,
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

// ListProjectFactsByAsset 返回当前资产事实和项目级公共事实。
func (db *DB) ListProjectFactsByAsset(
	ctx context.Context,
	projectID string,
	assetID string,
) ([]ProjectFact, error) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return db.ListProjectFacts(ctx, projectID)
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ?
		   AND (asset_id = ? OR asset_id = '')
		   AND valid_to = 0
		 ORDER BY updated_at DESC`,
		projectID,
		assetID,
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

func (db *DB) ListProjectFactsPage(
	ctx context.Context,
	projectID string,
	limit int,
	offset int,
) ([]ProjectFact, int, error) {
	return db.ListProjectFactsPageByAsset(ctx, projectID, "", limit, offset)
}

// ListProjectFactsPageByAsset 按资产分页；assetID 为空时返回项目全量事实。
func (db *DB) ListProjectFactsPageByAsset(
	ctx context.Context,
	projectID string,
	assetID string,
	limit int,
	offset int,
) ([]ProjectFact, int, error) {
	limit, offset = normalizeProjectPage(limit, offset)
	assetID = strings.TrimSpace(assetID)
	where := `project_id = ? AND valid_to = 0`
	args := []interface{}{projectID}
	if assetID != "" {
		where += ` AND (asset_id = ? OR asset_id = '')`
		args = append(args, assetID)
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_facts WHERE `+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	pageArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE `+where+`
		 ORDER BY updated_at DESC, rowid DESC
		 LIMIT ? OFFSET ?`,
		pageArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]ProjectFact, 0)
	for rows.Next() {
		item, scanErr := scanProjectFact(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (db *DB) UpdateProjectFact(ctx context.Context, item ProjectFact) error {
	item.Summary = strings.TrimSpace(item.Summary)
	item.Value = strings.TrimSpace(item.Value)
	if item.Summary == "" {
		item.Summary = item.Value
	}
	item.Value = item.Summary
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET fact_type = ?, value = ?, summary = ?,
			body = CASE WHEN ? = '' THEN body ELSE ? END,
			evidence = CASE WHEN ? = '' THEN evidence ELSE ? END,
				relation = CASE WHEN ? = '' THEN relation ELSE ? END,
				confidence = ?,
				memory_kind = CASE WHEN ? = '' THEN memory_kind ELSE ? END,
				priority = CASE WHEN ? <= 0 THEN priority ELSE ? END,
				pinned = CASE WHEN ? = 1 THEN 1 ELSE pinned END,
				observed_at = CASE WHEN ? <= 0 THEN observed_at ELSE ? END,
				contradicted_by = CASE WHEN ? = '' THEN contradicted_by ELSE ? END,
				conflict_reason = CASE WHEN ? = '' THEN conflict_reason ELSE ? END,
				subject_type = CASE WHEN ? = '' THEN subject_type ELSE ? END,
				subject_key = CASE WHEN ? = '' THEN subject_key ELSE ? END,
				predicate = CASE WHEN ? = '' THEN predicate ELSE ? END,
				object_type = CASE WHEN ? = '' THEN object_type ELSE ? END,
				object_key = CASE WHEN ? = '' THEN object_key ELSE ? END,
				updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		item.FactType,
		item.Value,
		item.Summary,
		item.Body,
		item.Body,
		item.Evidence,
		item.Evidence,
		item.Relation,
		item.Relation,
		item.Confidence,
		item.MemoryKind,
		item.MemoryKind,
		item.Priority,
		item.Priority,
		boolToInt(item.Pinned),
		item.ObservedAt.Unix(),
		item.ObservedAt.Unix(),
		item.ContradictedBy,
		item.ContradictedBy,
		item.ConflictReason,
		item.ConflictReason,
		item.SubjectType,
		item.SubjectType,
		item.SubjectKey,
		item.SubjectKey,
		item.Predicate,
		item.Predicate,
		item.ObjectType,
		item.ObjectType,
		item.ObjectKey,
		item.ObjectKey,
		item.UpdatedAt.Unix(),
		item.ID,
		item.ProjectID,
	)
	return requireAffected(result, err)
}

func (db *DB) DeleteProjectFact(ctx context.Context, id, projectID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var key string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT key FROM project_facts WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	).Scan(&key); err != nil {
		return err
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_facts WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}
	var nodeID string
	err = tx.QueryRowContext(
		ctx,
		`SELECT id FROM project_graph_nodes
		 WHERE project_id = ? AND kind = 'fact' AND title = ?`,
		projectID,
		key,
	).Scan(&nodeID)
	if err == nil {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM project_graph_edges WHERE project_id = ? AND (src_id = ? OR dst_id = ?)`,
			projectID,
			nodeID,
			nodeID,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM project_graph_nodes WHERE id = ? AND project_id = ?`,
			nodeID,
			projectID,
		); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return tx.Commit()
}

func (db *DB) CreateAsset(ctx context.Context, item Asset) error {
	if err := normalizeNewAssetRecord(&item); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	duplicate, err := assetDuplicateExists(ctx, tx, item, "")
	if err != nil {
		return err
	}
	if duplicate {
		return ErrAssetDuplicate
	}
	if err := markCrossTypeAssetQuality(ctx, tx, &item); err != nil {
		return err
	}
	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ProjectID,
		item.OwnerUserID,
		item.Name,
		item.Kind,
		item.Value,
		item.NormalizedValue,
		item.QualityStatus,
		item.Status,
		item.Source,
		item.Criticality,
		item.RiskScore,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ListAssets(ctx context.Context, ownerUserID string) ([]Asset, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets
		 WHERE owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')
		 ORDER BY updated_at DESC`,
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
		if !validStoredAsset(item) {
			continue
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListAssetsPage(
	ctx context.Context,
	ownerUserID string,
	limit int,
	offset int,
) ([]Asset, int, error) {
	limit, offset = normalizeProjectPage(limit, offset)
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets
		 WHERE owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')`,
		ownerUserID,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets
		 WHERE owner_user_id = ?
		   AND LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')
		 ORDER BY updated_at DESC, rowid DESC
		 LIMIT ? OFFSET ?`,
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

type AssetFilter struct {
	OwnerUserID string
	ProjectID   string
	Kind        string
	Status      string
	Search      string
	Sort        string
	Limit       int
	Offset      int
}

func (db *DB) ListAssetsFiltered(
	ctx context.Context,
	filter AssetFilter,
) ([]Asset, int, error) {
	clauses := []string{
		"owner_user_id = ?",
		"LOWER(TRIM(kind)) IN ('domain', 'ip', 'url', 'host', 'source')",
	}
	args := []interface{}{filter.OwnerUserID}
	if value := strings.TrimSpace(filter.ProjectID); value != "" {
		clauses = append(clauses, "project_id = ?")
		args = append(args, value)
	}
	if value := strings.ToLower(strings.TrimSpace(filter.Kind)); value != "" {
		clauses = append(clauses, "LOWER(TRIM(kind)) = ?")
		args = append(args, value)
	}
	if value := strings.ToLower(strings.TrimSpace(filter.Status)); value != "" {
		clauses = append(clauses, "LOWER(TRIM(status)) = ?")
		args = append(args, value)
	}
	if value := strings.TrimSpace(filter.Search); value != "" {
		pattern := "%" + escapeLikePattern(value) + "%"
		clauses = append(
			clauses,
			`(name LIKE ? ESCAPE '\' OR value LIKE ? ESCAPE '\' OR kind LIKE ? ESCAPE '\')`,
		)
		args = append(args, pattern, pattern, pattern)
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets`+where+`
		 ORDER BY updated_at DESC, rowid DESC`,
		args...,
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
		if !validStoredAsset(item) {
			continue
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, right := items[i], items[j]
		switch strings.ToLower(strings.TrimSpace(filter.Sort)) {
		case "updated_asc":
			return left.UpdatedAt.Before(right.UpdatedAt)
		case "name_asc":
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		case "name_desc":
			return strings.ToLower(left.Name) > strings.ToLower(right.Name)
		case "risk_desc":
			if left.RiskScore == right.RiskScore {
				return left.UpdatedAt.After(right.UpdatedAt)
			}
			return left.RiskScore > right.RiskScore
		case "risk_asc":
			if left.RiskScore == right.RiskScore {
				return left.UpdatedAt.After(right.UpdatedAt)
			}
			return left.RiskScore < right.RiskScore
		case "criticality_desc":
			leftRank, rightRank := assetCriticalityRank(left.Criticality), assetCriticalityRank(right.Criticality)
			if leftRank == rightRank {
				return left.UpdatedAt.After(right.UpdatedAt)
			}
			return leftRank > rightRank
		case "criticality_asc":
			leftRank, rightRank := assetCriticalityRank(left.Criticality), assetCriticalityRank(right.Criticality)
			if leftRank == rightRank {
				return left.UpdatedAt.After(right.UpdatedAt)
			}
			return leftRank < rightRank
		default:
			return left.UpdatedAt.After(right.UpdatedAt)
		}
	})
	total := len(items)
	limit, offset := normalizeProjectPage(filter.Limit, filter.Offset)
	if offset >= total {
		return []Asset{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return items[offset:end], total, nil
}

func assetCriticalityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func validStoredAsset(item Asset) bool {
	if !IsSupportedAssetKind(item.Kind) {
		return false
	}
	_, err := NormalizeAssetValue(item.Kind, item.Value)
	return err == nil
}

func (db *DB) GetAsset(ctx context.Context, id, ownerUserID string) (*Asset, error) {
	var item Asset
	var createdAt int64
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
			criticality, risk_score, created_at, updated_at
		 FROM assets
		 WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(
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
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

func (db *DB) DeleteAsset(ctx context.Context, id, ownerUserID string) (*AssetDeleteImpact, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var projectID string
	var name string
	var value string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT project_id, name, value FROM assets WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(&projectID, &name, &value); err != nil {
		return nil, err
	}
	impact, err := assetDeleteImpact(ctx, tx, projectID, ownerUserID, id, name, value)
	if err != nil {
		return nil, err
	}
	if err := deleteAssetOwnedData(ctx, tx, projectID, ownerUserID, id); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM assets WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	)
	if err := requireAffected(result, err); err != nil {
		return nil, err
	}
	if err := insertAssetDeleteAudit(ctx, tx, ownerUserID, impact); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return impact, nil
}

type assetDeleteQueryer interface {
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func (db *DB) AssetDeleteImpact(
	ctx context.Context,
	id string,
	ownerUserID string,
) (*AssetDeleteImpact, error) {
	var projectID, name, value string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id, name, value FROM assets WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(&projectID, &name, &value); err != nil {
		return nil, err
	}
	return assetDeleteImpact(ctx, db, projectID, ownerUserID, id, name, value)
}

func assetDeleteImpact(
	ctx context.Context,
	queryer assetDeleteQueryer,
	projectID string,
	ownerUserID string,
	assetID string,
	name string,
	value string,
) (*AssetDeleteImpact, error) {
	impact := &AssetDeleteImpact{
		AssetID:    assetID,
		ProjectID:  projectID,
		AssetName:  name,
		AssetValue: value,
	}
	normalizedAssetID := strings.ToLower(strings.TrimSpace(assetID))
	factQuery := `SELECT COUNT(*) FROM project_facts
		WHERE project_id = ? AND (
			asset_id = ? OR LOWER(TRIM(relation)) IN (?, ?)
		)`
	counts := []struct {
		target *int64
		query  string
		args   []interface{}
	}{
		{
			target: &impact.Intents,
			query:  `SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = ? AND asset_id = ? AND kind = 'intent'`,
			args:   []interface{}{projectID, assetID},
		},
		{
			target: &impact.Facts,
			query:  factQuery,
			args:   []interface{}{projectID, assetID, "asset_id:" + normalizedAssetID, "asset:" + normalizedAssetID},
		},
		{
			target: &impact.MemoryEntities,
			query: `SELECT COUNT(*) FROM project_memory_entities
				WHERE project_id = ? AND source_ref_id IN (
					SELECT id FROM project_facts
					WHERE project_id = ? AND (
						asset_id = ? OR LOWER(TRIM(relation)) IN (?, ?)
					)
				)`,
			args: []interface{}{
				projectID,
				projectID,
				assetID,
				"asset_id:" + normalizedAssetID,
				"asset:" + normalizedAssetID,
			},
		},
		{
			target: &impact.Findings,
			query:  `SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
			args:   []interface{}{projectID, ownerUserID, assetID},
		},
		{
			target: &impact.Tests,
			query:  `SELECT COUNT(*) FROM project_test_results WHERE project_id = ? AND asset_id = ?`,
			args:   []interface{}{projectID, assetID},
		},
		{
			target: &impact.GraphNodes,
			query: `SELECT COUNT(*) FROM project_graph_nodes
				WHERE project_id = ? AND (
					asset_id = ?
					OR source_ref_id IN (
						SELECT id FROM project_facts
						WHERE project_id = ? AND (
							asset_id = ? OR LOWER(TRIM(relation)) IN (?, ?)
						)
					)
					OR source_ref_id IN (
						SELECT id FROM vulnerabilities WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
					)
				)`,
			args: []interface{}{
				projectID,
				assetID,
				projectID,
				assetID,
				"asset_id:" + normalizedAssetID,
				"asset:" + normalizedAssetID,
				projectID,
				ownerUserID,
				assetID,
			},
		},
		{
			target: &impact.Conversations,
			query:  `SELECT COUNT(*) FROM conversations WHERE project_id = ? AND asset_id = ?`,
			args:   []interface{}{projectID, assetID},
		},
		{
			target: &impact.VulnerabilityFPs,
			query: `SELECT COUNT(*) FROM vulnerability_fingerprints
				WHERE project_id = ? AND vulnerability_id IN (
					SELECT id FROM vulnerabilities WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
				)`,
			args: []interface{}{projectID, projectID, ownerUserID, assetID},
		},
	}
	for _, item := range counts {
		if err := queryCount(ctx, queryer, item.query, item.target, item.args...); err != nil {
			return nil, err
		}
	}
	campaignQueries := []struct {
		query string
		args  []interface{}
	}{
		{`SELECT COUNT(*) FROM campaign_tasks WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`, []interface{}{projectID, ownerUserID, assetID}},
		{`SELECT COUNT(*) FROM campaign_endpoints WHERE project_id = ? AND asset_id = ?`, []interface{}{projectID, assetID}},
		{`SELECT COUNT(*) FROM campaign_frontier WHERE asset_id = ?`, []interface{}{assetID}},
		{`SELECT COUNT(*) FROM campaign_links WHERE project_id = ? AND (src_asset_id = ? OR dst_asset_id = ?)`, []interface{}{projectID, assetID, assetID}},
		{`SELECT COUNT(*) FROM campaign_coverage WHERE asset_id = ?`, []interface{}{assetID}},
		{
			`SELECT COUNT(*) FROM campaign_chains
			 WHERE project_id = ? AND (
				entry_asset_id = ? OR target_asset_id = ?
				OR id IN (SELECT chain_id FROM campaign_chain_steps WHERE asset_id = ?)
			 )`,
			[]interface{}{projectID, assetID, assetID, assetID},
		},
	}
	for _, item := range campaignQueries {
		var count int64
		if err := queryCount(ctx, queryer, item.query, &count, item.args...); err != nil {
			return nil, err
		}
		impact.CampaignRecords += count
	}
	return impact, nil
}

func queryCount(
	ctx context.Context,
	queryer assetDeleteQueryer,
	query string,
	target *int64,
	args ...interface{},
) error {
	return queryer.QueryRowContext(ctx, query, args...).Scan(target)
}

func insertAssetDeleteAudit(
	ctx context.Context,
	tx *sql.Tx,
	ownerUserID string,
	impact *AssetDeleteImpact,
) error {
	username := ownerUserID
	if err := tx.QueryRowContext(
		ctx,
		`SELECT username FROM users WHERE id = ?`,
		ownerUserID,
	).Scan(&username); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	detail := fmt.Sprintf(
		"asset=%s; intents=%d; facts=%d; memory_entities=%d; findings=%d; tests=%d; graph_nodes=%d; campaign_records=%d; conversations=%d; vulnerability_fingerprints=%d",
		impact.AssetValue,
		impact.Intents,
		impact.Facts,
		impact.MemoryEntities,
		impact.Findings,
		impact.Tests,
		impact.GraphNodes,
		impact.CampaignRecords,
		impact.Conversations,
		impact.VulnerabilityFPs,
	)
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_logs (
			id, user_id, username, action, resource_type, resource_id, result, detail, created_at
		) VALUES (?, ?, ?, 'asset.delete_cascade', 'asset', ?, 'success', ?, ?)`,
		newID(),
		ownerUserID,
		username,
		impact.AssetID,
		detail,
		time.Now().UTC().Unix(),
	)
	return err
}

func deleteAssetOwnedData(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	ownerUserID string,
	assetID string,
) error {
	normalizedAssetID := strings.ToLower(strings.TrimSpace(assetID))
	relationPatterns := []string{
		"asset_id:" + normalizedAssetID,
		"asset:" + normalizedAssetID,
	}
	factArgs := []interface{}{projectID, assetID}
	for _, pattern := range relationPatterns {
		factArgs = append(factArgs, pattern)
	}
	factIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT id FROM project_facts
		 WHERE project_id = ?
		   AND (asset_id = ? OR LOWER(TRIM(relation)) IN (`+placeholders(len(relationPatterns))+`))`,
		factArgs...,
	)
	if err != nil {
		return err
	}
	memoryEntityIDs, err := queryMemoryEntityIDsByFactIDs(ctx, tx, projectID, factIDs)
	if err != nil {
		return err
	}
	testResultIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT id FROM project_test_results WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	)
	if err != nil {
		return err
	}
	vulnerabilityIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT id FROM vulnerabilities WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		projectID,
		ownerUserID,
		assetID,
	)
	if err != nil {
		return err
	}
	nodeIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT id FROM project_graph_nodes WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	)
	if err != nil {
		return err
	}
	nodeIDSet := make(map[string]bool, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeIDSet[id] = true
	}
	for _, sourceIDs := range [][]string{factIDs, vulnerabilityIDs} {
		for start := 0; start < len(sourceIDs); start += assetDeleteIDBatchSize {
			end := minInt(start+assetDeleteIDBatchSize, len(sourceIDs))
			args := []interface{}{projectID}
			for _, id := range sourceIDs[start:end] {
				args = append(args, id)
			}
			related, err := queryStringColumn(
				ctx,
				tx,
				`SELECT id FROM project_graph_nodes
				 WHERE project_id = ? AND source_ref_id IN (`+placeholders(end-start)+`)`,
				args...,
			)
			if err != nil {
				return err
			}
			for _, id := range related {
				if !nodeIDSet[id] {
					nodeIDSet[id] = true
					nodeIDs = append(nodeIDs, id)
				}
			}
		}
	}
	campaignTaskIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT id FROM campaign_tasks WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		projectID,
		ownerUserID,
		assetID,
	)
	if err != nil {
		return err
	}
	campaignChainIDs, err := queryStringColumn(
		ctx,
		tx,
		`SELECT DISTINCT id FROM campaign_chains
		 WHERE project_id = ?
		   AND (
		     entry_asset_id = ? OR target_asset_id = ?
		     OR id IN (SELECT chain_id FROM campaign_chain_steps WHERE asset_id = ?)
		   )`,
		projectID,
		assetID,
		assetID,
		assetID,
	)
	if err != nil {
		return err
	}

	if err := deleteRowsByIDs(ctx, tx, "vulnerability_images", "vulnerability_id", vulnerabilityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerability_retests", "vulnerability_id", vulnerabilityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerability_fingerprints", "vulnerability_id", vulnerabilityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerability_report_drafts", "vulnerability_id", vulnerabilityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerability_report_drafts", "intent_id", nodeIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerability_report_drafts", "hypothesis_id", testResultIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_verifications", "finding_id", vulnerabilityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_verifications", "task_id", campaignTaskIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_frontier", "task_id", campaignTaskIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_frontier WHERE asset_id = ?`,
		assetID,
	); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_chain_steps", "chain_id", campaignChainIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_chain_steps WHERE asset_id = ?`,
		assetID,
	); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_chains", "id", campaignChainIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_links WHERE project_id = ? AND (src_asset_id = ? OR dst_asset_id = ?)`,
		projectID,
		assetID,
		assetID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_coverage WHERE asset_id = ?`,
		assetID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_endpoints WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "campaign_tasks", "id", campaignTaskIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_memory_digests
		 WHERE project_id = ? AND scope_type = 'asset' AND scope_id = ?`,
		projectID,
		assetID,
	); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_fact_versions", "fact_id", factIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "memory_writes", "fact_id", factIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_memory_relations", "fact_id", factIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_memory_relations", "src_entity_id", memoryEntityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_memory_relations", "dst_entity_id", memoryEntityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_memory_entities", "id", memoryEntityIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_facts", "id", factIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_graph_edges", "src_id", nodeIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_graph_edges", "dst_id", nodeIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "project_graph_nodes", "id", nodeIDs); err != nil {
		return err
	}
	if err := deleteRowsByIDs(ctx, tx, "vulnerabilities", "id", vulnerabilityIDs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_test_results WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_asset_work WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	); err != nil {
		return err
	}
	_, err = tx.ExecContext(
		ctx,
		`UPDATE conversations SET asset_id = '' WHERE project_id = ? AND asset_id = ?`,
		projectID,
		assetID,
	)
	return err
}

func queryStringColumn(
	ctx context.Context,
	tx *sql.Tx,
	query string,
	args ...interface{},
) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var item string
		if err := rows.Scan(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func queryMemoryEntityIDsByFactIDs(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	factIDs []string,
) ([]string, error) {
	entityIDs := make([]string, 0)
	seen := map[string]bool{}
	for start := 0; start < len(factIDs); start += assetDeleteIDBatchSize {
		end := minInt(start+assetDeleteIDBatchSize, len(factIDs))
		args := []interface{}{projectID}
		for _, id := range factIDs[start:end] {
			args = append(args, id)
		}
		items, err := queryStringColumn(
			ctx,
			tx,
			`SELECT id FROM project_memory_entities
			 WHERE project_id = ? AND source_ref_id IN (`+placeholders(end-start)+`)`,
			args...,
		)
		if err != nil {
			return nil, err
		}
		for _, id := range items {
			if !seen[id] {
				seen[id] = true
				entityIDs = append(entityIDs, id)
			}
		}
	}
	return entityIDs, nil
}

func deleteRowsByIDs(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	column string,
	ids []string,
) error {
	if !hasStringIDs(ids) {
		return nil
	}
	for start := 0; start < len(ids); start += assetDeleteIDBatchSize {
		end := minInt(start+assetDeleteIDBatchSize, len(ids))
		args := make([]interface{}, 0, end-start)
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM `+table+` WHERE `+column+` IN (`+placeholders(end-start)+`)`,
			args...,
		); err != nil {
			return err
		}
	}
	return nil
}

func hasStringIDs(ids []string) bool {
	for _, id := range ids {
		if strings.TrimSpace(id) != "" {
			return true
		}
	}
	return false
}

func (db *DB) UpdateAsset(ctx context.Context, item Asset) error {
	if err := normalizeNewAssetRecord(&item); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var oldProjectID string
	var oldName string
	var oldValue string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT project_id, name, value FROM assets WHERE id = ? AND owner_user_id = ?`,
		item.ID,
		item.OwnerUserID,
	).Scan(&oldProjectID, &oldName, &oldValue); err != nil {
		return err
	}
	duplicate, err := assetDuplicateExists(ctx, tx, item, item.ID)
	if err != nil {
		return err
	}
	if duplicate {
		return ErrAssetDuplicate
	}
	if err := markCrossTypeAssetQuality(ctx, tx, &item); err != nil {
		return err
	}
	if oldProjectID != item.ProjectID {
		inUse, err := assetHasReferences(ctx, tx, item, oldProjectID, oldName, oldValue)
		if err != nil {
			return err
		}
		if inUse {
			return ErrAssetInUse
		}
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE assets
			 SET project_id = ?, name = ?, kind = ?, value = ?, normalized_value = ?, quality_status = ?, status = ?,
			criticality = ?, risk_score = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		item.ProjectID,
		item.Name,
		item.Kind,
		item.Value,
		item.NormalizedValue,
		item.QualityStatus,
		item.Status,
		item.Criticality,
		item.RiskScore,
		item.UpdatedAt.Unix(),
		item.ID,
		item.OwnerUserID,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}
	if oldProjectID != "" {
		if err := canonicalizeAssetFactRelations(
			ctx,
			tx,
			oldProjectID,
			item.ID,
			oldName,
			oldValue,
		); err != nil {
			return err
		}
	}
	if oldProjectID != "" && oldProjectID != item.ProjectID {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM project_asset_work WHERE project_id = ? AND asset_id = ?`,
			oldProjectID,
			item.ID,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) CreateVulnerability(ctx context.Context, item Vulnerability) error {
	return insertVulnerability(ctx, db, item)
}

func (db *DB) ListVulnerabilities(ctx context.Context, ownerUserID string) ([]Vulnerability, error) {
	items, _, err := db.ListVulnerabilitiesFiltered(ctx, VulnerabilityFilter{
		OwnerUserID: ownerUserID,
		Limit:       200,
	})
	return items, err
}

func (db *DB) UpdateVulnerability(ctx context.Context, item Vulnerability) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := updateVulnerabilityTx(ctx, tx, item); err != nil {
		return err
	}
	return tx.Commit()
}

func updateVulnerabilityTx(
	ctx context.Context,
	tx *sql.Tx,
	item Vulnerability,
) error {
	item = NormalizeVulnerabilityEvidence(item)
	evidenceRefs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return err
	}
	var oldProjectID string
	var oldTitle string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT project_id, title FROM vulnerabilities
		 WHERE id = ? AND owner_user_id = ?`,
		item.ID,
		item.OwnerUserID,
	).Scan(&oldProjectID, &oldTitle); err != nil {
		return err
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE vulnerabilities
		 SET project_id = ?, asset_id = ?, title = ?, severity = ?, status = ?,
			vulnerability_type = ?, target = ?, parameter = ?, http_method = ?, preconditions = ?,
			reproduction_steps = ?, description = ?, evidence = ?,
				evidence_refs = CASE WHEN ? = '[]' THEN evidence_refs ELSE ? END,
				impact = ?,
				recommendation = ?, retest_notes = ?,
				fingerprint = ?, verification_state = ?, confidence = ?,
				exploitability = ?, test_technique = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		item.ProjectID,
		item.AssetID,
		item.Title,
		item.Severity,
		item.Status,
		item.VulnerabilityType,
		item.Target,
		item.Parameter,
		item.HTTPMethod,
		item.Preconditions,
		item.ReproductionSteps,
		item.Description,
		item.Evidence,
		evidenceRefs,
		evidenceRefs,
		item.Impact,
		item.Recommendation,
		item.RetestNotes,
		item.Fingerprint,
		item.VerificationState,
		item.Confidence,
		item.Exploitability,
		item.TestTechnique,
		item.UpdatedAt.Unix(),
		item.ID,
		item.OwnerUserID,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}
	if oldProjectID != item.ProjectID {
		if err := deleteVulnerabilityGraphNode(
			ctx,
			tx,
			oldProjectID,
			item.ID,
			oldTitle,
		); err != nil {
			return err
		}
	}
	if err := upsertVulnerabilityGraphNode(ctx, tx, item); err != nil {
		return err
	}
	return nil
}

func (db *DB) DeleteVulnerability(ctx context.Context, id, ownerUserID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var projectID string
	var title string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT project_id, title FROM vulnerabilities
		 WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(&projectID, &title); err != nil {
		return err
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM vulnerabilities WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM vulnerability_fingerprints WHERE vulnerability_id = ?`,
		id,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_test_results WHERE project_id = ? AND finding_id = ?`,
		projectID,
		id,
	); err != nil {
		return err
	}
	if err := deleteVulnerabilityGraphNode(ctx, tx, projectID, id, title); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) VulnerabilityStats(ctx context.Context, ownerUserID string) (map[string]int, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT severity, COUNT(*) FROM vulnerabilities
		 WHERE owner_user_id = ? GROUP BY severity`,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		result[severity] = count
	}
	return result, rows.Err()
}

func (db *DB) CreateKnowledgeItem(ctx context.Context, item KnowledgeItem) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO knowledge_items (
			id, owner_user_id, category, title, content, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.OwnerUserID,
		item.Category,
		item.Title,
		item.Content,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) ListKnowledgeItems(ctx context.Context, ownerUserID string) ([]KnowledgeItem, error) {
	return db.queryKnowledge(ctx, ownerUserID, "", false)
}

func (db *DB) SearchKnowledgeItems(
	ctx context.Context,
	ownerUserID string,
	query string,
) ([]KnowledgeItem, error) {
	return db.queryKnowledge(ctx, ownerUserID, query, true)
}

func (db *DB) queryKnowledge(
	ctx context.Context,
	ownerUserID string,
	query string,
	search bool,
) ([]KnowledgeItem, error) {
	sqlText := `SELECT id, owner_user_id, category, title, content, created_at, updated_at
		FROM knowledge_items WHERE owner_user_id = ?`
	args := []interface{}{ownerUserID}
	if search {
		like := "%" + strings.TrimSpace(query) + "%"
		sqlText += ` AND (title LIKE ? OR content LIKE ? OR category LIKE ?)`
		args = append(args, like, like, like)
	}
	sqlText += ` ORDER BY updated_at DESC LIMIT 200`

	rows, err := db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]KnowledgeItem, 0)
	for rows.Next() {
		var item KnowledgeItem
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.Category,
			&item.Title,
			&item.Content,
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

func (db *DB) GetKnowledgeItem(
	ctx context.Context,
	id string,
	ownerUserID string,
) (*KnowledgeItem, error) {
	var item KnowledgeItem
	var createdAt int64
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, owner_user_id, category, title, content, created_at, updated_at
		 FROM knowledge_items
		 WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.Category,
		&item.Title,
		&item.Content,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

func (db *DB) UpdateKnowledgeItem(ctx context.Context, item KnowledgeItem) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE knowledge_items
		 SET category = ?, title = ?, content = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		item.Category,
		item.Title,
		item.Content,
		item.UpdatedAt.Unix(),
		item.ID,
		item.OwnerUserID,
	)
	return requireAffected(result, err)
}

func (db *DB) CreateWebShellConnection(ctx context.Context, item WebShellConnection) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO webshell_connections (
			id, project_id, owner_user_id, name, url, method, password,
			encoding, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ProjectID,
		item.OwnerUserID,
		item.Name,
		item.URL,
		item.Method,
		item.Password,
		item.Encoding,
		item.Status,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) ListWebShellConnections(
	ctx context.Context,
	ownerUserID string,
) ([]WebShellConnection, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, url, method, password,
			encoding, status, created_at, updated_at
		 FROM webshell_connections
		 WHERE owner_user_id = ?
		 ORDER BY updated_at DESC`,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]WebShellConnection, 0)
	for rows.Next() {
		var item WebShellConnection
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Name,
			&item.URL,
			&item.Method,
			&item.Password,
			&item.Encoding,
			&item.Status,
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

func (db *DB) DeleteWebShellConnection(ctx context.Context, id, ownerUserID string) error {
	_, err := db.ExecContext(
		ctx,
		`DELETE FROM webshell_connections WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	)
	return err
}

func NoRows(err error) bool {
	return err == sql.ErrNoRows
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func RequireString(value, field string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}
