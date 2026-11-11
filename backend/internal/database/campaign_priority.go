package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RecomputeCampaignScheduling 统一刷新业务系统优先级、任务 ROI 与调度优先级。
func (db *DB) RecomputeCampaignScheduling(ctx context.Context, campaignID string) error {
	if err := db.RecomputeGroupPriorities(ctx, campaignID); err != nil {
		return err
	}
	if err := db.RecomputeFrontierROI(ctx, campaignID); err != nil {
		return err
	}
	return db.RecomputeCampaignPriorities(ctx, campaignID)
}

// RecomputeGroupPriorities 按业务优先级、漏洞风险、覆盖缺口和凭据价值计算资产组优先级。
func (db *DB) RecomputeGroupPriorities(ctx context.Context, campaignID string) error {
	if strings.TrimSpace(campaignID) == "" {
		return nil
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT g.id,
			g.business_priority,
			COALESCE(MAX(CASE LOWER(v.severity)
				WHEN 'critical' THEN 40
				WHEN 'high' THEN 30
				WHEN 'medium' THEN 15
				WHEN 'low' THEN 5
				ELSE 0 END), 0) AS severity_bonus,
			COALESCE(MAX(a.risk_score), 0) AS max_risk
		 FROM campaign_groups g
		 LEFT JOIN campaign_endpoints e ON e.group_id = g.id
		 LEFT JOIN assets a ON a.id = e.asset_id
		 LEFT JOIN vulnerabilities v
		   ON v.asset_id = e.asset_id
		  AND LOWER(COALESCE(v.status, '')) NOT IN ('false_positive', 'closed', 'ignored')
		 WHERE g.campaign_id = ?
		 GROUP BY g.id`,
		campaignID,
	)
	if err != nil {
		return err
	}
	type groupScore struct {
		id              string
		business        int
		severityBonus   int
		maxRisk         int
		coverageGap     int
		credentialCount int
	}
	scores := make(map[string]*groupScore)
	for rows.Next() {
		item := &groupScore{}
		if err := rows.Scan(&item.id, &item.business, &item.severityBonus, &item.maxRisk); err != nil {
			_ = rows.Close()
			return err
		}
		scores[item.id] = item
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if len(scores) == 0 {
		return nil
	}

	coverageRows, err := db.QueryContext(
		ctx,
		`SELECT e.group_id,
			COUNT(DISTINCT e.asset_id) AS assets,
			COUNT(DISTINCT CASE
				WHEN LOWER(COALESCE(c.status, '')) IN ('tested_clean', 'confirmed', 'blocked', 'suspicious')
				THEN e.asset_id END) AS covered
		 FROM campaign_endpoints e
		 LEFT JOIN campaign_coverage c
		   ON c.campaign_id = e.campaign_id AND c.asset_id = e.asset_id
		 WHERE e.campaign_id = ?
		 GROUP BY e.group_id`,
		campaignID,
	)
	if err != nil {
		return err
	}
	for coverageRows.Next() {
		var groupID string
		var assets, covered int
		if err := coverageRows.Scan(&groupID, &assets, &covered); err != nil {
			_ = coverageRows.Close()
			return err
		}
		if score := scores[groupID]; score != nil && assets > 0 {
			score.coverageGap = (assets - covered) * 15 / assets
		}
	}
	if err := coverageRows.Err(); err != nil {
		_ = coverageRows.Close()
		return err
	}
	_ = coverageRows.Close()

	credentialRows, err := db.QueryContext(
		ctx,
		`SELECT e.group_id, COUNT(*)
		 FROM project_facts f
		 JOIN campaign_endpoints e
		   ON e.campaign_id = ? AND e.asset_id = f.asset_id
		 WHERE f.project_id = (
			SELECT project_id FROM conversation_batches WHERE id = ?
		 )
		   AND (
			LOWER(COALESCE(f.memory_kind, '')) = 'credential'
			OR LOWER(COALESCE(f.fact_type, '')) LIKE '%credential%'
			OR LOWER(COALESCE(f.key, '')) LIKE '%password%'
			OR LOWER(COALESCE(f.key, '')) LIKE '%credential%'
		   )
		 GROUP BY e.group_id`,
		campaignID,
		campaignID,
	)
	if err != nil {
		return err
	}
	for credentialRows.Next() {
		var groupID string
		var count int
		if err := credentialRows.Scan(&groupID, &count); err != nil {
			_ = credentialRows.Close()
			return err
		}
		if score := scores[groupID]; score != nil {
			score.credentialCount = count
		}
	}
	if err := credentialRows.Err(); err != nil {
		_ = credentialRows.Close()
		return err
	}
	_ = credentialRows.Close()

	now := time.Now().UTC()
	for _, score := range scores {
		base := score.business
		if base <= 0 {
			base = 35 + score.maxRisk/2
		}
		credentialBonus := 0
		if score.credentialCount > 0 {
			credentialBonus = 10
		}
		value := base + score.severityBonus + score.coverageGap + credentialBonus
		if value > 100 {
			value = 100
		}
		if value < 0 {
			value = 0
		}
		reason := fmt.Sprintf(
			"业务 %d + 漏洞风险 %d + 覆盖缺口 %d + 凭据 %d",
			base,
			score.severityBonus,
			score.coverageGap,
			credentialBonus,
		)
		if _, err := db.ExecContext(
			ctx,
			`UPDATE campaign_groups
			 SET priority_score = ?, priority_reason = ?, priority_updated_at = ?
			 WHERE id = ? AND campaign_id = ?`,
			value,
			reason,
			now.Unix(),
			score.id,
			campaignID,
		); err != nil {
			return err
		}
	}
	return nil
}

// SetCampaignGroupPriority 设置业务系统名称和人工业务优先级。
func (db *DB) SetCampaignGroupPriority(
	ctx context.Context,
	campaignID string,
	groupID string,
	businessSystem string,
	businessPriority int,
) (*CampaignGroup, error) {
	if businessPriority < 0 {
		businessPriority = 0
	}
	if businessPriority > 100 {
		businessPriority = 100
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE campaign_groups
		 SET business_system = ?, business_priority = ?, updated_at = ?
		 WHERE id = ? AND campaign_id = ?`,
		strings.TrimSpace(businessSystem),
		businessPriority,
		time.Now().UTC().Unix(),
		groupID,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, fmt.Errorf("资产组不存在")
	}
	if err := db.RecomputeGroupPriorities(ctx, campaignID); err != nil {
		return nil, err
	}
	items, err := db.ListCampaignGroups(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	for index := range items {
		if items[index].ID == groupID {
			return &items[index], nil
		}
	}
	return nil, fmt.Errorf("资产组不存在")
}

// RecomputeFrontierROI 计算 Frontier 的期望价值、预计成本和投入产出比。
func (db *DB) RecomputeFrontierROI(ctx context.Context, campaignID string) error {
	if strings.TrimSpace(campaignID) == "" {
		return nil
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT f.id, f.kind, f.priority,
			COALESCE(t.max_tool_calls, 60),
			COALESCE(t.attempts, 0),
			COALESCE(g.priority_score, 50)
		 FROM campaign_frontier f
		 LEFT JOIN campaign_tasks t ON t.id = f.task_id
		 LEFT JOIN campaign_groups g ON g.id = f.group_id
		 WHERE f.campaign_id = ? AND f.status IN ('pending', 'running')`,
		campaignID,
	)
	if err != nil {
		return err
	}
	type roiItem struct {
		id    string
		value int
		cost  int
		roi   int
	}
	items := make([]roiItem, 0)
	for rows.Next() {
		var id, kind string
		var priority, maxToolCalls, attempts, groupPriority int
		if err := rows.Scan(
			&id,
			&kind,
			&priority,
			&maxToolCalls,
			&attempts,
			&groupPriority,
		); err != nil {
			_ = rows.Close()
			return err
		}
		value := frontierBaseValue(kind)
		if priority > value {
			value = priority
		}
		value += groupPriority / 5
		if value > 100 {
			value = 100
		}
		cost := maxToolCalls / 10
		if cost < 1 {
			cost = 1
		}
		cost += attempts * 3
		roi := value * 100 / cost
		if roi > 999 {
			roi = 999
		}
		items = append(items, roiItem{id: id, value: value, cost: cost, roi: roi})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, item := range items {
		if _, err := db.ExecContext(
			ctx,
			`UPDATE campaign_frontier
			 SET expected_value = ?, estimated_cost = ?, roi = ?
			 WHERE id = ?`,
			item.value,
			item.cost,
			item.roi,
			item.id,
		); err != nil {
			return err
		}
	}
	return nil
}

func frontierBaseValue(kind string) int {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "verify_finding":
		return 90
	case "chain_test":
		return 90
	case "credential_reuse":
		return 85
	case "pivot_test":
		return 80
	case "endpoint_scan":
		return 65
	case "asset_scan":
		return 55
	case "group_plan":
		return 45
	case "campaign_review":
		return 40
	case "reporting":
		return 30
	default:
		return 50
	}
}

func frontierExpectedValue(kind string, priority int) int {
	value := frontierBaseValue(kind)
	if priority > value {
		value = priority
	}
	if value > 100 {
		value = 100
	}
	if value < 0 {
		value = 0
	}
	return value
}

func frontierEstimatedCost(limits CampaignTaskLimits) int {
	cost := limits.MaxToolCalls / 10
	if cost < 1 {
		cost = 1
	}
	return cost
}

func frontierROI(value int, cost int) int {
	if cost < 1 {
		cost = 1
	}
	roi := value * 100 / cost
	if roi > 999 {
		roi = 999
	}
	return roi
}
