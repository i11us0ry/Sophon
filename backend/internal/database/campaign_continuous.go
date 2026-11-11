package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	CampaignModeSingle     = "single"
	CampaignModeContinuous = "continuous"

	CampaignStatusStopped = "stopped"
)

// AddCampaignToolCalls 累计战役级工具调用消耗，用于持续战役总预算控制。
func (db *DB) AddCampaignToolCalls(ctx context.Context, campaignID string, delta int) error {
	if delta <= 0 {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET campaign_tool_calls = campaign_tool_calls + ?, updated_at = ?
		 WHERE id = ?`,
		delta,
		time.Now().UTC().Unix(),
		strings.TrimSpace(campaignID),
	)
	return err
}

// SyncCampaignToolCalls 以任务明细为准重算战役累计工具调用，避免重复累计。
func (db *DB) SyncCampaignToolCalls(ctx context.Context, campaignID string) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET campaign_tool_calls = COALESCE((
			SELECT SUM(tool_calls) FROM campaign_tasks WHERE campaign_id = ?
		 ), 0),
		 updated_at = ?
		 WHERE id = ?`,
		campaignID,
		time.Now().UTC().Unix(),
		campaignID,
	)
	return err
}

// CountToolExecutionsSince 统计某个会话在指定时间之后实际执行的工具调用数量。
func (db *DB) CountToolExecutionsSince(
	ctx context.Context,
	conversationID string,
	since time.Time,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM process_details
		 WHERE conversation_id = ? AND event_type = 'tool_call' AND created_at >= ?`,
		strings.TrimSpace(conversationID),
		since.UTC().Unix(),
	).Scan(&count)
	return count, err
}

// AdvanceCampaignRound 递增持续战役轮次，并返回递增后的轮次。
func (db *DB) AdvanceCampaignRound(ctx context.Context, campaignID string) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var current int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT campaign_round FROM conversation_batches WHERE id = ?`,
		campaignID,
	).Scan(&current); err != nil {
		return 0, err
	}
	current++
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET campaign_round = ?, updated_at = ?
		 WHERE id = ?`,
		current,
		time.Now().UTC().Unix(),
		campaignID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return current, nil
}

// StopCampaign 手动停止战役，保留全部进度和任务记录。
func (db *DB) StopCampaign(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
) error {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, stopped_at = ?, finished_at = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		CampaignStatusStopped,
		now,
		now,
		now,
		strings.TrimSpace(campaignID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CreateCampaignReviewTask 在战役队列清空后创建一次 Planner 复盘任务。
func (db *DB) CreateCampaignReviewTask(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
	round int,
) (*CampaignTask, error) {
	var projectID, conversationID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id, parent_conversation_id
		 FROM conversation_batches
		 WHERE id = ? AND owner_user_id = ?`,
		campaignID,
		ownerUserID,
	).Scan(&projectID, &conversationID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(conversationID) == "" {
		return nil, fmt.Errorf("战役缺少父对话")
	}
	intent, _ := json.Marshal(map[string]interface{}{
		"kind":  "campaign_review",
		"round": round,
		"scope": "读取覆盖率、漏洞、攻击链和失败记录，生成下一轮 Frontier 候选任务",
	})
	now := time.Now().UTC()
	taskID := newID()
	if _, err := db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO campaign_tasks (
			id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts,
				max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
			) VALUES (?, ?, '', '', ?, ?, ?, 'campaign_review', '', 'campaign_round',
				?, ?, 'queued', 75, 0, 1, 6, 80, 0, '', '', 0, '', 0, 0, ?, ?)`,
		taskID,
		campaignID,
		conversationID,
		projectID,
		ownerUserID,
		strconv.Itoa(round),
		string(intent),
		now.Unix(),
		now.Unix(),
	); err != nil {
		return nil, err
	}
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts,
				max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
		 FROM campaign_tasks
		 WHERE campaign_id = ? AND kind = 'campaign_review' AND source_ref = ?
		 LIMIT 1`,
		campaignID,
		strconv.Itoa(round),
	)
	item, err := scanCampaignTask(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}
