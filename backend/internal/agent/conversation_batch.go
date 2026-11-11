package agent

import (
	"context"
	"fmt"
	"strings"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func (s *Service) conversationBatchBriefing(
	ctx context.Context,
	conversationID string,
	userID string,
) string {
	if s == nil || s.db == nil {
		return ""
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		return ""
	}
	conversationKind := strings.TrimSpace(conversation.Kind)
	if conversationKind != "batch_child" && conversationKind != "batch_parent" {
		return ""
	}
	batch, err := s.db.GetConversationBatchByChildConversation(ctx, conversationID, userID)
	if err != nil || batch == nil {
		return ""
	}
	target := ""
	if asset, err := s.db.GetAsset(ctx, conversation.AssetID, userID); err == nil && asset != nil {
		target = strings.TrimSpace(asset.Value)
	}
	var builder strings.Builder
	builder.WriteString("\n\n批量任务上下文：\n")
	if target != "" {
		builder.WriteString(fmt.Sprintf("- 当前资产：%s\n", target))
	}
	builder.WriteString(fmt.Sprintf("- 批次：%s\n", batch.Title))
	var task *database.CampaignTask
	if taskID := strings.TrimSpace(execctx.CampaignTaskID(ctx)); taskID != "" {
		if item, err := s.db.GetCampaignTaskByID(ctx, taskID, userID); err == nil {
			task = item
		}
	}
	if task == nil {
		if item, err := s.db.GetCampaignTaskByConversation(ctx, conversationID, userID); err == nil {
			task = item
		}
	}
	if conversationKind == "batch_parent" &&
		(task == nil || task.Kind != "campaign_review") {
		return ""
	}
	if task != nil {
		builder.WriteString(fmt.Sprintf(
			"- Campaign 任务：%s，类型 %s，状态 %s，尝试 %d/%d，预算 %d 段 / %d 次工具调用\n",
			task.ID,
			task.Kind,
			task.Status,
			task.Attempts,
			task.MaxAttempts,
			task.MaxSegments,
			task.MaxToolCalls,
		))
		if intent := strings.TrimSpace(task.IntentJSON); intent != "" && intent != "{}" {
			builder.WriteString(fmt.Sprintf("- 本轮子任务意图（%s）：%s\n", task.Kind, intent))
			switch task.Kind {
			case "verify_finding":
				builder.WriteString(
					"- 本轮仅做证据核验与最小化复现；完成后必须用 project_verify_finding 写回状态和证据。\n",
				)
			case "credential_reuse":
				builder.WriteString(
					"- 本轮只允许对 Campaign 内已授权资产验证凭据复用；结果写入 project_record_test，成功后补充事实或漏洞证据。\n",
				)
			case "chain_test":
				builder.WriteString(
					"- 本轮逐步验证攻击链。每一步都必须有证据，失败步骤用 project_record_test 记录 tested_clean 或 blocked；成功后补充事实、漏洞和 project_record_link。\n",
				)
			case "campaign_review":
				builder.WriteString(
					"- 本轮为持续战役复盘：读取覆盖率、未完成目标、漏洞、攻击链和失败记录；" +
						"用 project_plan_frontier 生成下一轮候选任务，不要重复已完成或已覆盖的方向。\n",
				)
			}
		}
	}
	builder.WriteString("- 任务要求：")
	builder.WriteString(batch.Instruction)
	return builder.String()
}
