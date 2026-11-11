package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	CampaignChainStatusCandidate = "candidate"
	CampaignChainStatusTesting   = "testing"
	CampaignChainStatusVerified  = "verified"
	CampaignChainStatusFailed    = "failed"
)

type CampaignChain struct {
	ID            string              `json:"id"`
	CampaignID    string              `json:"campaignId"`
	ProjectID     string              `json:"projectId"`
	Fingerprint   string              `json:"fingerprint"`
	Title         string              `json:"title"`
	Kind          string              `json:"kind"`
	Status        string              `json:"status"`
	Priority      int                 `json:"priority"`
	Confidence    int                 `json:"confidence"`
	EntryAssetID  string              `json:"entryAssetId"`
	TargetAssetID string              `json:"targetAssetId"`
	SrcFindingID  string              `json:"srcFindingId"`
	SrcFactID     string              `json:"srcFactId"`
	EvidenceRefs  []string            `json:"evidenceRefs"`
	Steps         []CampaignChainStep `json:"steps,omitempty"`
	CreatedAt     time.Time           `json:"createdAt"`
	UpdatedAt     time.Time           `json:"updatedAt"`
}

type CampaignChainStep struct {
	ID        string    `json:"id"`
	ChainID   string    `json:"chainId"`
	StepOrder int       `json:"stepOrder"`
	Kind      string    `json:"kind"`
	AssetID   string    `json:"assetId"`
	SourceRef string    `json:"sourceRef"`
	Summary   string    `json:"summary"`
	CreatedAt time.Time `json:"createdAt"`
}

type campaignChainCandidate struct {
	srcAssetID   string
	dstAssetID   string
	linkKind     string
	summary      string
	confidence   int
	srcFactID    string
	srcFindingID string
	severity     string
	findingTitle string
	findingState string
}

func (db *DB) CreateCampaignChain(ctx context.Context, chain CampaignChain) (*CampaignChain, error) {
	chain.CampaignID = strings.TrimSpace(chain.CampaignID)
	chain.ProjectID = strings.TrimSpace(chain.ProjectID)
	chain.Fingerprint = strings.TrimSpace(chain.Fingerprint)
	chain.Title = strings.TrimSpace(chain.Title)
	if chain.CampaignID == "" || chain.Fingerprint == "" || chain.Title == "" {
		return nil, fmt.Errorf("campaign、fingerprint 和 title 不能为空")
	}
	chain.Kind = strings.TrimSpace(chain.Kind)
	if chain.Status == "" {
		chain.Status = CampaignChainStatusCandidate
	}
	if chain.Priority <= 0 {
		chain.Priority = 50
	}
	if chain.Priority > 100 {
		chain.Priority = 100
	}
	if chain.Confidence <= 0 {
		chain.Confidence = 60
	}
	if chain.Confidence > 100 {
		chain.Confidence = 100
	}
	refs, err := encodeEvidenceRefs(chain.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	if chain.ID == "" {
		chain.ID = newID()
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO campaign_chains (
			id, campaign_id, project_id, fingerprint, title, kind, status,
			priority, confidence, entry_asset_id, target_asset_id,
			src_finding_id, src_fact_id, evidence_refs, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, fingerprint) DO UPDATE SET
			title = excluded.title,
			kind = excluded.kind,
			priority = MAX(campaign_chains.priority, excluded.priority),
			confidence = MAX(campaign_chains.confidence, excluded.confidence),
			entry_asset_id = excluded.entry_asset_id,
			target_asset_id = excluded.target_asset_id,
			src_finding_id = excluded.src_finding_id,
			src_fact_id = excluded.src_fact_id,
			evidence_refs = CASE
				WHEN excluded.evidence_refs = '[]' THEN campaign_chains.evidence_refs
				ELSE excluded.evidence_refs
			END,
			updated_at = excluded.updated_at`,
		chain.ID,
		chain.CampaignID,
		chain.ProjectID,
		chain.Fingerprint,
		chain.Title,
		chain.Kind,
		chain.Status,
		chain.Priority,
		chain.Confidence,
		chain.EntryAssetID,
		chain.TargetAssetID,
		chain.SrcFindingID,
		chain.SrcFactID,
		refs,
		now.Unix(),
		now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	for index, step := range chain.Steps {
		stepID := chain.ID + "-" + strconv.Itoa(index)
		if _, err := db.ExecContext(
			ctx,
			`INSERT INTO campaign_chain_steps (
				id, chain_id, step_order, kind, asset_id, source_ref, summary, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				step_order = excluded.step_order,
				kind = excluded.kind,
				asset_id = excluded.asset_id,
				source_ref = excluded.source_ref,
				summary = excluded.summary`,
			stepID,
			chain.ID,
			index,
			step.Kind,
			step.AssetID,
			step.SourceRef,
			step.Summary,
			now.Unix(),
		); err != nil {
			return nil, err
		}
	}
	return db.GetCampaignChainByFingerprint(ctx, chain.CampaignID, chain.Fingerprint)
}

func (db *DB) GetCampaignChainByFingerprint(
	ctx context.Context,
	campaignID string,
	fingerprint string,
) (*CampaignChain, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, project_id, fingerprint, title, kind, status,
			priority, confidence, entry_asset_id, target_asset_id,
			src_finding_id, src_fact_id, evidence_refs, created_at, updated_at
		 FROM campaign_chains
		 WHERE campaign_id = ? AND fingerprint = ?`,
		campaignID,
		fingerprint,
	)
	item, err := scanCampaignChain(row)
	if err != nil {
		return nil, err
	}
	steps, err := db.listCampaignChainSteps(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	item.Steps = steps
	return item, nil
}

func (db *DB) ListCampaignChains(
	ctx context.Context,
	campaignID string,
	limit int,
) ([]CampaignChain, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, fingerprint, title, kind, status,
			priority, confidence, entry_asset_id, target_asset_id,
			src_finding_id, src_fact_id, evidence_refs, created_at, updated_at
		 FROM campaign_chains
		 WHERE campaign_id = ?
		 ORDER BY
			CASE status WHEN 'testing' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,
			priority DESC, updated_at DESC
		 LIMIT ?`,
		campaignID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignChain, 0)
	for rows.Next() {
		item, err := scanCampaignChain(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stepsByChain, err := db.listCampaignChainStepsBatch(ctx, campaignChainIDs(items))
	if err != nil {
		return nil, err
	}
	for index := range items {
		items[index].Steps = stepsByChain[items[index].ID]
	}
	return items, nil
}

func (db *DB) ListProjectCampaignChains(
	ctx context.Context,
	projectID string,
	limit int,
) ([]CampaignChain, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, fingerprint, title, kind, status,
			priority, confidence, entry_asset_id, target_asset_id,
			src_finding_id, src_fact_id, evidence_refs, created_at, updated_at
		 FROM campaign_chains
		 WHERE project_id = ?
		 ORDER BY
			CASE status WHEN 'testing' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,
			priority DESC, updated_at DESC
		 LIMIT ?`,
		strings.TrimSpace(projectID),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignChain, 0)
	for rows.Next() {
		item, err := scanCampaignChain(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stepsByChain, err := db.listCampaignChainStepsBatch(ctx, campaignChainIDs(items))
	if err != nil {
		return nil, err
	}
	for index := range items {
		items[index].Steps = stepsByChain[items[index].ID]
	}
	return items, nil
}

func campaignChainIDs(items []CampaignChain) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ID) != "" {
			ids = append(ids, item.ID)
		}
	}
	return ids
}

func (db *DB) listCampaignChainStepsBatch(
	ctx context.Context,
	chainIDs []string,
) (map[string][]CampaignChainStep, error) {
	result := make(map[string][]CampaignChainStep, len(chainIDs))
	if len(chainIDs) == 0 {
		return result, nil
	}
	query := `SELECT id, chain_id, step_order, kind, asset_id, source_ref, summary, created_at
		FROM campaign_chain_steps
		WHERE chain_id IN (` + placeholders(len(chainIDs)) + `)
		ORDER BY chain_id ASC, step_order ASC`
	args := buildIDArgs(nil, chainIDs)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item CampaignChainStep
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ChainID,
			&item.StepOrder,
			&item.Kind,
			&item.AssetID,
			&item.SourceRef,
			&item.Summary,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		result[item.ChainID] = append(result[item.ChainID], item)
	}
	return result, rows.Err()
}

func (db *DB) listCampaignChainSteps(
	ctx context.Context,
	chainID string,
) ([]CampaignChainStep, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, chain_id, step_order, kind, asset_id, source_ref, summary, created_at
		 FROM campaign_chain_steps
		 WHERE chain_id = ?
		 ORDER BY step_order ASC`,
		chainID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	steps := make([]CampaignChainStep, 0)
	for rows.Next() {
		var item CampaignChainStep
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ChainID,
			&item.StepOrder,
			&item.Kind,
			&item.AssetID,
			&item.SourceRef,
			&item.Summary,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		steps = append(steps, item)
	}
	return steps, rows.Err()
}

func (db *DB) UpdateCampaignChainStatus(
	ctx context.Context,
	campaignID string,
	chainID string,
	status string,
	evidenceRefs []string,
) (*CampaignChain, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case CampaignChainStatusCandidate,
		CampaignChainStatusTesting,
		CampaignChainStatusVerified,
		CampaignChainStatusFailed:
	default:
		return nil, fmt.Errorf("攻击链状态不合法")
	}
	refs, err := encodeEvidenceRefs(evidenceRefs)
	if err != nil {
		return nil, err
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE campaign_chains
		 SET status = ?,
		     evidence_refs = CASE WHEN ? = '[]' THEN evidence_refs ELSE ? END,
		     updated_at = ?
		 WHERE id = ? AND campaign_id = ?`,
		status,
		refs,
		refs,
		time.Now().UTC().Unix(),
		chainID,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, fmt.Errorf("攻击链不存在")
	}
	return db.GetCampaignChainByID(ctx, campaignID, chainID)
}

func (db *DB) GetCampaignChainByID(
	ctx context.Context,
	campaignID string,
	chainID string,
) (*CampaignChain, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, project_id, fingerprint, title, kind, status,
			priority, confidence, entry_asset_id, target_asset_id,
			src_finding_id, src_fact_id, evidence_refs, created_at, updated_at
		 FROM campaign_chains
		 WHERE campaign_id = ? AND id = ?`,
		campaignID,
		chainID,
	)
	item, err := scanCampaignChain(row)
	if err != nil {
		return nil, err
	}
	steps, err := db.listCampaignChainSteps(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	item.Steps = steps
	return item, nil
}

type campaignChainRow interface {
	Scan(dest ...interface{}) error
}

func scanCampaignChain(row campaignChainRow) (*CampaignChain, error) {
	var item CampaignChain
	var refs string
	var createdAt, updatedAt int64
	if err := row.Scan(
		&item.ID,
		&item.CampaignID,
		&item.ProjectID,
		&item.Fingerprint,
		&item.Title,
		&item.Kind,
		&item.Status,
		&item.Priority,
		&item.Confidence,
		&item.EntryAssetID,
		&item.TargetAssetID,
		&item.SrcFindingID,
		&item.SrcFactID,
		&refs,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(refs)
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

// GenerateCampaignChains 根据跨资产关系和漏洞证据生成可执行攻击链。
func (db *DB) GenerateCampaignChains(ctx context.Context, campaignID string) (int, error) {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return 0, nil
	}
	var projectID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id FROM conversation_batches WHERE id = ?`,
		campaignID,
	).Scan(&projectID); err != nil {
		return 0, err
	}
	campaignAssets := map[string]bool{}
	assetRows, err := db.QueryContext(
		ctx,
		`SELECT DISTINCT asset_id FROM campaign_endpoints WHERE campaign_id = ?`,
		campaignID,
	)
	if err != nil {
		return 0, err
	}
	for assetRows.Next() {
		var assetID string
		if err := assetRows.Scan(&assetID); err != nil {
			_ = assetRows.Close()
			return 0, err
		}
		campaignAssets[assetID] = true
	}
	if err := assetRows.Err(); err != nil {
		_ = assetRows.Close()
		return 0, err
	}
	_ = assetRows.Close()
	rows, err := db.QueryContext(
		ctx,
		`SELECT l.src_asset_id, l.dst_asset_id, l.kind, l.summary, l.confidence,
			l.src_fact_id, l.src_finding_id,
			COALESCE(v.severity, ''), COALESCE(v.title, ''), COALESCE(v.status, '')
		 FROM campaign_links l
		 LEFT JOIN vulnerabilities v ON v.id = l.src_finding_id
		 WHERE l.campaign_id = ?
		 ORDER BY l.updated_at DESC
		 LIMIT 300`,
		campaignID,
	)
	if err != nil {
		return 0, err
	}
	candidates := make([]campaignChainCandidate, 0)
	for rows.Next() {
		var item campaignChainCandidate
		if err := rows.Scan(
			&item.srcAssetID,
			&item.dstAssetID,
			&item.linkKind,
			&item.summary,
			&item.confidence,
			&item.srcFactID,
			&item.srcFindingID,
			&item.severity,
			&item.findingTitle,
			&item.findingState,
		); err != nil {
			_ = rows.Close()
			return 0, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	created := 0
	for _, candidate := range candidates {
		if !campaignAssets[candidate.srcAssetID] || !campaignAssets[candidate.dstAssetID] {
			continue
		}
		chainKind := chainKindForLink(candidate.linkKind)
		if chainKind == "" {
			continue
		}
		priority := candidate.confidence
		if priority <= 0 {
			priority = 60
		}
		severityBonus := chainSeverityBonus(candidate.severity)
		priority += severityBonus
		if priority > 100 {
			priority = 100
		}
		fingerprint := strings.Join([]string{
			chainKind,
			candidate.srcAssetID,
			candidate.dstAssetID,
			candidate.srcFindingID,
			candidate.srcFactID,
		}, ":")
		title := chainTitle(chainKind, candidate.findingTitle)
		steps := []CampaignChainStep{
			{
				Kind:      "entry",
				AssetID:   candidate.srcAssetID,
				SourceRef: candidate.srcFindingID,
				Summary:   chainStepSummary(candidate, true),
			},
			{
				Kind:      "pivot",
				AssetID:   candidate.dstAssetID,
				SourceRef: candidate.srcFactID,
				Summary:   chainStepSummary(candidate, false),
			},
		}
		chain, err := db.CreateCampaignChain(ctx, CampaignChain{
			CampaignID:    campaignID,
			ProjectID:     projectID,
			Fingerprint:   fingerprint,
			Title:         title,
			Kind:          chainKind,
			Status:        CampaignChainStatusCandidate,
			Priority:      priority,
			Confidence:    candidate.confidence,
			EntryAssetID:  candidate.srcAssetID,
			TargetAssetID: candidate.dstAssetID,
			SrcFindingID:  candidate.srcFindingID,
			SrcFactID:     candidate.srcFactID,
			EvidenceRefs:  chainEvidenceRefs(candidate),
			Steps:         steps,
		})
		if err != nil {
			return created, err
		}
		intent, _ := json.Marshal(map[string]interface{}{
			"kind":            "chain_test",
			"chain_id":        chain.ID,
			"entry_asset_id":  chain.EntryAssetID,
			"target_asset_id": chain.TargetAssetID,
			"chain_kind":      chain.Kind,
			"src_finding_id":  chain.SrcFindingID,
			"src_fact_id":     chain.SrcFactID,
		})
		if _, err := db.EnqueueCampaignFrontier(ctx, CampaignFrontierItem{
			CampaignID: campaignID,
			AssetID:    chain.EntryAssetID,
			Kind:       "chain_test",
			Priority:   priority,
			Reason:     "验证攻击链：" + chain.Title,
			DedupeKey:  "chain_test:" + fingerprint,
			SourceType: "chain",
			SourceRef:  chain.ID,
			IntentJSON: string(intent),
		}, CampaignTaskLimits{
			MaxAttempts:  1,
			MaxSegments:  6,
			MaxToolCalls: 80,
		}); err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

func chainKindForLink(linkKind string) string {
	switch strings.ToLower(strings.TrimSpace(linkKind)) {
	case "credential_reuse":
		return "credential_reuse"
	case "ssrf_to":
		return "ssrf_pivot"
	case "pivot", "lateral_move", "shared_infra":
		return "finding_pivot"
	default:
		return ""
	}
}

func chainSeverityBonus(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 30
	case "high":
		return 20
	case "medium":
		return 10
	default:
		return 0
	}
}

func chainTitle(kind string, findingTitle string) string {
	switch kind {
	case "credential_reuse":
		return "凭据复用链"
	case "ssrf_pivot":
		return "SSRF 内网跳转链"
	default:
		if strings.TrimSpace(findingTitle) != "" {
			return "漏洞横向链：" + strings.TrimSpace(findingTitle)
		}
		return "跨资产横向移动链"
	}
}

func chainStepSummary(candidate campaignChainCandidate, entry bool) string {
	if entry {
		if strings.TrimSpace(candidate.findingTitle) != "" {
			return "入口：" + strings.TrimSpace(candidate.findingTitle)
		}
		if strings.TrimSpace(candidate.summary) != "" {
			return "入口：" + strings.TrimSpace(candidate.summary)
		}
		return "入口资产 " + candidate.srcAssetID
	}
	if strings.TrimSpace(candidate.summary) != "" {
		return "关系：" + strings.TrimSpace(candidate.summary)
	}
	return "目标资产 " + candidate.dstAssetID
}

func chainEvidenceRefs(candidate campaignChainCandidate) []string {
	refs := make([]string, 0, 3)
	if strings.TrimSpace(candidate.srcFindingID) != "" {
		refs = append(refs, "finding:"+candidate.srcFindingID)
	}
	if strings.TrimSpace(candidate.srcFactID) != "" {
		refs = append(refs, "fact:"+candidate.srcFactID)
	}
	refs = append(refs, "asset:"+candidate.srcAssetID, "asset:"+candidate.dstAssetID)
	return refs
}
