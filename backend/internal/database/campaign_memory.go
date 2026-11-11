package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	CampaignMemoryTierHot  = "hot"
	CampaignMemoryTierCold = "cold"
)

type CampaignMemoryDigest struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaignId"`
	ProjectID   string    `json:"projectId"`
	ScopeType   string    `json:"scopeType"`
	ScopeID     string    `json:"scopeId"`
	Tier        string    `json:"tier"`
	Kind        string    `json:"kind"`
	Summary     string    `json:"summary"`
	PayloadJSON string    `json:"payloadJson"`
	SourceCount int       `json:"sourceCount"`
	Freshness   int       `json:"freshness"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (db *DB) UpsertCampaignMemoryDigest(
	ctx context.Context,
	item CampaignMemoryDigest,
) (*CampaignMemoryDigest, error) {
	item.CampaignID = strings.TrimSpace(item.CampaignID)
	item.ScopeType = strings.TrimSpace(item.ScopeType)
	item.ScopeID = strings.TrimSpace(item.ScopeID)
	item.Kind = strings.TrimSpace(item.Kind)
	if item.CampaignID == "" || item.ScopeType == "" || item.Kind == "" {
		return nil, fmt.Errorf("campaign、scope_type 和 kind 不能为空")
	}
	if item.Tier != CampaignMemoryTierCold {
		item.Tier = CampaignMemoryTierHot
	}
	if item.Freshness < 0 {
		item.Freshness = 0
	}
	if item.Freshness > 100 {
		item.Freshness = 100
	}
	if strings.TrimSpace(item.PayloadJSON) == "" {
		item.PayloadJSON = "{}"
	}
	if item.ID == "" {
		item.ID = newID()
	}
	now := time.Now().UTC()
	expiresAt := int64(0)
	if !item.ExpiresAt.IsZero() {
		expiresAt = item.ExpiresAt.Unix()
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO campaign_memory_digests (
			id, campaign_id, project_id, scope_type, scope_id, tier, kind,
			summary, payload_json, source_count, freshness, expires_at,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, scope_type, scope_id, kind) DO UPDATE SET
			tier = excluded.tier,
			summary = excluded.summary,
			payload_json = excluded.payload_json,
			source_count = excluded.source_count,
			freshness = excluded.freshness,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`,
		item.ID,
		item.CampaignID,
		item.ProjectID,
		item.ScopeType,
		item.ScopeID,
		item.Tier,
		item.Kind,
		item.Summary,
		item.PayloadJSON,
		item.SourceCount,
		item.Freshness,
		expiresAt,
		now.Unix(),
		now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	return db.GetCampaignMemoryDigest(ctx, item.CampaignID, item.ScopeType, item.ScopeID, item.Kind)
}

func (db *DB) GetCampaignMemoryDigest(
	ctx context.Context,
	campaignID string,
	scopeType string,
	scopeID string,
	kind string,
) (*CampaignMemoryDigest, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, project_id, scope_type, scope_id, tier, kind,
			summary, payload_json, source_count, freshness, expires_at,
			created_at, updated_at
		 FROM campaign_memory_digests
		 WHERE campaign_id = ? AND scope_type = ? AND scope_id = ? AND kind = ?`,
		campaignID,
		scopeType,
		scopeID,
		kind,
	)
	var item CampaignMemoryDigest
	var expiresAt, createdAt, updatedAt int64
	if err := row.Scan(
		&item.ID,
		&item.CampaignID,
		&item.ProjectID,
		&item.ScopeType,
		&item.ScopeID,
		&item.Tier,
		&item.Kind,
		&item.Summary,
		&item.PayloadJSON,
		&item.SourceCount,
		&item.Freshness,
		&expiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	item.ExpiresAt = unixTimeOrZero(expiresAt)
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	redactCampaignMemoryPayload(&item)
	return &item, nil
}

func redactCampaignMemoryPayload(item *CampaignMemoryDigest) {
	if item != nil && item.Kind == "credentials" {
		item.PayloadJSON = "{}"
	}
}

func (db *DB) ListCampaignMemoryDigests(
	ctx context.Context,
	campaignID string,
	tier string,
	limit int,
) ([]CampaignMemoryDigest, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	where := `campaign_id = ?`
	args := []interface{}{campaignID}
	tier = strings.ToLower(strings.TrimSpace(tier))
	if tier == CampaignMemoryTierHot || tier == CampaignMemoryTierCold {
		where += ` AND tier = ?`
		args = append(args, tier)
	}
	args = append(args, limit)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, scope_type, scope_id, tier, kind,
			summary, payload_json, source_count, freshness, expires_at,
			created_at, updated_at
		 FROM campaign_memory_digests
		 WHERE `+where+`
		 ORDER BY freshness DESC, updated_at DESC
		 LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignMemoryDigest, 0)
	for rows.Next() {
		var item CampaignMemoryDigest
		var expiresAt, createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.ProjectID,
			&item.ScopeType,
			&item.ScopeID,
			&item.Tier,
			&item.Kind,
			&item.Summary,
			&item.PayloadJSON,
			&item.SourceCount,
			&item.Freshness,
			&expiresAt,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.ExpiresAt = unixTimeOrZero(expiresAt)
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		redactCampaignMemoryPayload(&item)
		items = append(items, item)
	}
	return items, rows.Err()
}

// QueryCampaignMemory 按关键字在长期记忆摘要中检索，供 Agent 冷数据按需读取。
func (db *DB) QueryCampaignMemory(
	ctx context.Context,
	campaignID string,
	keyword string,
	limit int,
) ([]CampaignMemoryDigest, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return db.ListCampaignMemoryDigests(ctx, campaignID, "", limit)
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, scope_type, scope_id, tier, kind,
			summary, payload_json, source_count, freshness, expires_at,
			created_at, updated_at
		 FROM campaign_memory_digests
		 WHERE campaign_id = ?
		   AND (summary LIKE ? OR payload_json LIKE ? OR scope_id LIKE ?)
		 ORDER BY freshness DESC, updated_at DESC
		 LIMIT ?`,
		campaignID,
		"%"+keyword+"%",
		"%"+keyword+"%",
		"%"+keyword+"%",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignMemoryDigest, 0)
	for rows.Next() {
		var item CampaignMemoryDigest
		var expiresAt, createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.ProjectID,
			&item.ScopeType,
			&item.ScopeID,
			&item.Tier,
			&item.Kind,
			&item.Summary,
			&item.PayloadJSON,
			&item.SourceCount,
			&item.Freshness,
			&expiresAt,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.ExpiresAt = unixTimeOrZero(expiresAt)
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		redactCampaignMemoryPayload(&item)
		items = append(items, item)
	}
	return items, rows.Err()
}

// RefreshCampaignMemory 生成战役级热记忆索引与冷数据索引，不删除或搬移原始业务数据。
func (db *DB) RefreshCampaignMemory(ctx context.Context, campaignID string) error {
	campaignID = strings.TrimSpace(campaignID)
	if campaignID == "" {
		return nil
	}
	var projectID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id FROM conversation_batches WHERE id = ?`,
		campaignID,
	).Scan(&projectID); err != nil {
		return err
	}
	summary, err := db.CampaignSummary(ctx, campaignID)
	if err != nil {
		return err
	}
	chainCount := 0
	_ = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_chains WHERE campaign_id = ?`,
		campaignID,
	).Scan(&chainCount)
	payload, _ := json.Marshal(map[string]interface{}{
		"totalAssets":       summary.TotalAssets,
		"totalGroups":       summary.TotalGroups,
		"queuedTasks":       summary.QueuedTasks,
		"runningTasks":      summary.RunningTasks,
		"completedTasks":    summary.CompletedTasks,
		"failedTasks":       summary.FailedTasks,
		"coverageTotal":     summary.CoverageTotal,
		"coverageCompleted": summary.CoverageCompleted,
		"chains":            chainCount,
		"campaignMode":      summary.CampaignMode,
		"campaignRound":     summary.CampaignRound,
	})
	coveragePercent := 0
	if summary.CoverageTotal > 0 {
		coveragePercent = summary.CoverageCompleted * 100 / summary.CoverageTotal
	}
	if _, err := db.UpsertCampaignMemoryDigest(ctx, CampaignMemoryDigest{
		CampaignID: campaignID,
		ProjectID:  projectID,
		ScopeType:  "campaign",
		ScopeID:    campaignID,
		Tier:       CampaignMemoryTierHot,
		Kind:       "summary",
		Summary: fmt.Sprintf(
			"战役：资产 %d，组 %d，任务 %d/%d 完成，覆盖率 %d%%，攻击链 %d，轮次 %d/%d",
			summary.TotalAssets,
			summary.TotalGroups,
			summary.CompletedTasks,
			summary.TotalAssets,
			coveragePercent,
			chainCount,
			summary.CampaignRound,
			summary.MaxRounds,
		),
		PayloadJSON: string(payload),
		SourceCount: summary.TotalAssets,
		Freshness:   100,
	}); err != nil {
		return err
	}

	findingRows, err := db.QueryContext(
		ctx,
		`SELECT title, severity, status, asset_id
		 FROM vulnerabilities
		 WHERE project_id = ?
		 ORDER BY CASE LOWER(severity)
		    WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
		    updated_at DESC
		 LIMIT 10`,
		projectID,
	)
	if err != nil {
		return err
	}
	findings := make([]map[string]string, 0)
	findingSummary := make([]string, 0)
	for findingRows.Next() {
		var title, severity, status, assetID string
		if err := findingRows.Scan(&title, &severity, &status, &assetID); err != nil {
			_ = findingRows.Close()
			return err
		}
		findings = append(findings, map[string]string{
			"title": title, "severity": severity, "status": status, "assetId": assetID,
		})
		findingSummary = append(findingSummary, fmt.Sprintf("%s[%s]", title, severity))
	}
	if err := findingRows.Err(); err != nil {
		_ = findingRows.Close()
		return err
	}
	_ = findingRows.Close()
	findingPayload, _ := json.Marshal(findings)
	if _, err := db.UpsertCampaignMemoryDigest(ctx, CampaignMemoryDigest{
		CampaignID:  campaignID,
		ProjectID:   projectID,
		ScopeType:   "campaign",
		ScopeID:     campaignID,
		Tier:        CampaignMemoryTierHot,
		Kind:        "top_findings",
		Summary:     "高价值漏洞：" + strings.Join(findingSummary, "；"),
		PayloadJSON: string(findingPayload),
		SourceCount: len(findings),
		Freshness:   95,
	}); err != nil {
		return err
	}

	credentialRows, err := db.QueryContext(
		ctx,
		`SELECT key, COALESCE(summary, value), asset_id
			 FROM project_facts
			 WHERE project_id = ?
			   AND (valid_to = 0 OR valid_to > ?)
			   AND superseded_by = ''
			   AND (
			LOWER(COALESCE(memory_kind, '')) = 'credential'
			OR LOWER(COALESCE(fact_type, '')) LIKE '%credential%'
			OR LOWER(COALESCE(key, '')) LIKE '%password%'
			OR LOWER(COALESCE(key, '')) LIKE '%credential%'
			OR LOWER(COALESCE(key, '')) LIKE '%凭据%'
			OR LOWER(COALESCE(key, '')) LIKE '%密码%'
		   )
		 ORDER BY updated_at DESC
			 LIMIT 10`,
		projectID,
		time.Now().UTC().Unix(),
	)
	if err != nil {
		return err
	}
	credentials := make([]map[string]string, 0)
	credentialSummary := make([]string, 0)
	for credentialRows.Next() {
		var key, summary, assetID string
		if err := credentialRows.Scan(&key, &summary, &assetID); err != nil {
			_ = credentialRows.Close()
			return err
		}
		credentials = append(credentials, map[string]string{
			"key": key, "summary": summary, "assetId": assetID,
		})
		credentialSummary = append(credentialSummary, key)
	}
	if err := credentialRows.Err(); err != nil {
		_ = credentialRows.Close()
		return err
	}
	_ = credentialRows.Close()
	credentialPayload, _ := json.Marshal(credentials)
	if _, err := db.UpsertCampaignMemoryDigest(ctx, CampaignMemoryDigest{
		CampaignID:  campaignID,
		ProjectID:   projectID,
		ScopeType:   "campaign",
		ScopeID:     campaignID,
		Tier:        CampaignMemoryTierHot,
		Kind:        "credentials",
		Summary:     "已知凭据：" + strings.Join(credentialSummary, "；"),
		PayloadJSON: string(credentialPayload),
		SourceCount: len(credentials),
		Freshness:   90,
	}); err != nil {
		return err
	}

	var factCount, taskCount int
	var oldestFact, newestFact int64
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(MIN(updated_at), 0), COALESCE(MAX(updated_at), 0)
		 FROM project_facts WHERE project_id = ?`,
		projectID,
	).Scan(&factCount, &oldestFact, &newestFact); err != nil {
		return err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_tasks WHERE campaign_id = ?`,
		campaignID,
	).Scan(&taskCount); err != nil {
		return err
	}
	coldPayload, _ := json.Marshal(map[string]interface{}{
		"facts":        factCount,
		"tasks":        taskCount,
		"oldestFactAt": oldestFact,
		"newestFactAt": newestFact,
	})
	if _, err := db.UpsertCampaignMemoryDigest(ctx, CampaignMemoryDigest{
		CampaignID: campaignID,
		ProjectID:  projectID,
		ScopeType:  "campaign",
		ScopeID:    campaignID,
		Tier:       CampaignMemoryTierCold,
		Kind:       "historical_index",
		Summary: fmt.Sprintf(
			"历史数据索引：事实 %d 条，任务 %d 条；明细按需查询，不注入上下文",
			factCount,
			taskCount,
		),
		PayloadJSON: string(coldPayload),
		SourceCount: factCount + taskCount,
		Freshness:   20,
	}); err != nil {
		return err
	}
	return nil
}

func (db *DB) CampaignP2Counts(
	ctx context.Context,
	campaignID string,
) (chainCount int, hotCount int, coldCount int, err error) {
	if err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_chains WHERE campaign_id = ?`,
		campaignID,
	).Scan(&chainCount); err != nil {
		return
	}
	if err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_memory_digests
		 WHERE campaign_id = ? AND tier = 'hot'`,
		campaignID,
	).Scan(&hotCount); err != nil {
		return
	}
	err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_memory_digests
		 WHERE campaign_id = ? AND tier = 'cold'`,
		campaignID,
	).Scan(&coldCount)
	return
}
