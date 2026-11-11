package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// refreshCampaignIntelligence 刷新攻击链、长期记忆和调度评分；失败不阻塞主业务写回。
func (s *Service) refreshCampaignIntelligence(ctx context.Context, campaignID string) {
	campaignID = strings.TrimSpace(campaignID)
	if s == nil || s.db == nil || campaignID == "" {
		return
	}
	const refreshInterval = 5 * time.Second
	s.campaignRefreshMu.Lock()
	if s.campaignRefreshAt == nil {
		s.campaignRefreshAt = map[string]time.Time{}
	}
	last := s.campaignRefreshAt[campaignID]
	now := time.Now()
	if !last.IsZero() && now.Sub(last) < refreshInterval {
		s.campaignRefreshMu.Unlock()
		return
	}
	s.campaignRefreshAt[campaignID] = now
	s.campaignRefreshMu.Unlock()
	_, _ = s.db.GenerateCampaignChains(ctx, campaignID)
	_ = s.db.RefreshCampaignMemory(ctx, campaignID)
	_ = s.db.RecomputeCampaignScheduling(ctx, campaignID)
}

func (s *Service) setGroupPriorityTool() tool.BaseTool {
	return &jsonTool{
		name: "project_set_group_priority",
		desc: "设置业务系统名称和资产组业务优先级，影响 Frontier 与攻击链调度顺序。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id":       stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"group_id":          stringParam("资产组 id", true),
			"business_system":   stringParam("业务系统名称"),
			"business_priority": integerParam("业务优先级 1-100，默认 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID       string  `json:"campaign_id"`
				GroupID          string  `json:"group_id"`
				BusinessSystem   string  `json:"business_system"`
				BusinessPriority flexInt `json:"business_priority"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, err := s.resolveCampaignID(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "", fmt.Errorf("当前对话不属于批量任务")
			}
			priority := int(request.BusinessPriority)
			if priority <= 0 {
				priority = 50
			}
			if priority > 100 {
				priority = 100
			}
			group, err := s.db.SetCampaignGroupPriority(
				ctx,
				campaignID,
				request.GroupID,
				truncateProjectText(request.BusinessSystem, projectToolShortText),
				priority,
			)
			if err != nil {
				return "", err
			}
			s.refreshCampaignIntelligence(ctx, campaignID)
			return fmt.Sprintf(
				"资产组 %s 已更新：业务系统 %s，业务优先级 %d，综合优先级 %d（%s）",
				group.Label,
				group.BusinessSystem,
				group.BusinessPriority,
				group.PriorityScore,
				group.PriorityReason,
			), nil
		},
	}
}

func (s *Service) listChainsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_chains",
		desc: "查看自动生成的跨资产攻击链及其步骤。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id": stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"query":       stringParam("按标题、类型或资产搜索"),
			"status":      stringParam("按攻击链状态过滤"),
			"kind":        stringParam("按攻击链类型过滤"),
			"limit":       integerParam("返回条数，默认 20，最大 100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID string  `json:"campaign_id"`
				Query      string  `json:"query"`
				Status     string  `json:"status"`
				Kind       string  `json:"kind"`
				Limit      flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, err := s.resolveCampaignID(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "当前对话不属于批量任务。", nil
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 100 {
				limit = 20
			}
			query := strings.ToLower(strings.TrimSpace(request.Query))
			status := strings.ToLower(strings.TrimSpace(request.Status))
			kind := strings.ToLower(strings.TrimSpace(request.Kind))
			fetchLimit := limit
			if query != "" || status != "" || kind != "" {
				fetchLimit = 100
			}
			items, err := s.db.ListCampaignChains(ctx, campaignID, fetchLimit)
			if err != nil {
				return "", fmt.Errorf("读取攻击链失败: %w", err)
			}
			if len(items) == 0 {
				return "当前战役暂无攻击链。", nil
			}
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if status != "" && strings.ToLower(item.Status) != status {
					continue
				}
				if kind != "" && strings.ToLower(item.Kind) != kind {
					continue
				}
				if query != "" && !projectTextMatches(query, item.Title, item.Kind, item.Status, item.EntryAssetID, item.TargetAssetID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				builder.WriteString(fmt.Sprintf(
					"- [%d/%s] %s（%s，置信度 %d，入口 %s，目标 %s）\n",
					item.Priority,
					item.Status,
					item.Title,
					item.Kind,
					item.Confidence,
					item.EntryAssetID,
					item.TargetAssetID,
				))
				for _, step := range item.Steps {
					builder.WriteString(fmt.Sprintf(
						"  %d. %s %s %s\n",
						step.StepOrder+1,
						step.Kind,
						step.AssetID,
						step.Summary,
					))
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) queryMemoryTool() tool.BaseTool {
	return &jsonTool{
		name: "project_query_memory",
		desc: "按需检索战役长期记忆摘要，包括热数据和冷数据索引。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id": stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"keyword":     stringParam("检索关键字，可留空返回最近记忆"),
			"limit":       integerParam("返回条数，默认 20，最大 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID string  `json:"campaign_id"`
				Keyword    string  `json:"keyword"`
				Limit      flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, err := s.resolveCampaignID(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "当前对话不属于批量任务。", nil
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 50 {
				limit = 20
			}
			items, err := s.db.QueryCampaignMemory(
				ctx,
				campaignID,
				truncateProjectText(request.Keyword, projectToolShortText),
				limit,
			)
			if err != nil {
				return "", fmt.Errorf("检索长期记忆失败: %w", err)
			}
			if len(items) == 0 {
				return "没有匹配的长期记忆。", nil
			}
			var builder strings.Builder
			for _, item := range items {
				builder.WriteString(fmt.Sprintf(
					"- [%s/%s] %s（来源 %d，新鲜度 %d）\n",
					item.Tier,
					item.Kind,
					truncateProjectText(item.Summary, projectToolLongText),
					item.SourceCount,
					item.Freshness,
				))
				if payload := strings.TrimSpace(item.PayloadJSON); payload != "" && payload != "{}" {
					builder.WriteString("  payload: ")
					builder.WriteString(truncateProjectText(payload, projectToolLongText))
					builder.WriteString("\n")
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}
