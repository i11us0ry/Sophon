package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/vulnerabilityfmt"
)

const (
	projectToolListLimit   = 50
	projectToolOutputLimit = 6000
	projectToolShortText   = 200
	projectToolLongText    = 4000
	projectSyncDebounce    = 750 * time.Millisecond
	projectSyncTimeout     = 2 * time.Minute
)

type projectSyncState struct {
	dirty     bool
	running   bool
	scheduled bool
}

var (
	findingSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	graphNodeStatuses = map[string]map[string]bool{
		"goal": {"open": true, "met": true, "abandoned": true},
		"intent": {
			"open": true, "running": true, "done": true,
			"blocked": true, "exhausted": true, "capacity_blocked": true,
		},
		"hint": {"active": true, "consumed": true},
	}
)

// jsonTool 是多参数内置工具的通用实现：JSON 入参 + 文本结果。
type jsonTool struct {
	name   string
	desc   string
	params map[string]*schema.ParameterInfo
	run    func(ctx context.Context, raw string) (string, error)
}

func (t *jsonTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name:        t.name,
		Desc:        t.desc,
		ParamsOneOf: schema.NewParamsOneOfByParams(t.params),
	}, nil
}

func (t *jsonTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	_ ...tool.Option,
) (string, error) {
	return t.run(ctx, argumentsInJSON)
}

type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	value := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if value == "" || value == "null" {
		*f = 0
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("参数应为整数，实际为 %s", string(data))
	}
	*f = flexInt(parsed)
	return nil
}

func stringParam(desc string, required ...bool) *schema.ParameterInfo {
	isRequired := len(required) > 0 && required[0]
	return &schema.ParameterInfo{Type: schema.String, Desc: desc, Required: isRequired}
}

func integerParam(desc string) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.Integer, Desc: desc}
}

func stringEnumParam(desc string, values []string, required ...bool) *schema.ParameterInfo {
	isRequired := len(required) > 0 && required[0]
	return &schema.ParameterInfo{
		Type:     schema.String,
		Desc:     desc,
		Enum:     values,
		Required: isRequired,
	}
}

func stringArrayParam(desc string) *schema.ParameterInfo {
	return &schema.ParameterInfo{
		Type:     schema.Array,
		ElemInfo: &schema.ParameterInfo{Type: schema.String},
		Desc:     desc,
	}
}

// newProjectTools 构造项目数据读写工具：主 Agent 与渗透子 Agent 共用，
// 目标项目由当前会话（execctx）决定，未绑定项目时调用会返回明确错误。
func newProjectTools(service *Service) []tool.BaseTool {
	tools := []tool.BaseTool{
		service.projectListTool(),
		service.projectGetTool(),
		service.recordFactTool(),
		service.recordAuditTool(),
		service.insertAssetsTool(),
		service.reportFindingTool(),
		service.nextTargetsTool(),
		service.planHypothesesTool(),
		service.startHypothesisTool(),
		service.completeHypothesisTool(),
		service.recordTestResultTool(),
		service.upsertMemoryEntityTool(),
		service.linkMemoryEntitiesTool(),
		service.memoryGraphTool(),
		service.newFactAuditTool(),
		service.graphOverviewTool(),
		service.syncGraphTool(),
		service.campaignOverviewTool(),
		service.campaignFrontierTool(),
		service.planFrontierTool(),
		service.recordLinkTool(),
		service.verifyFindingTool(),
		service.setGroupPriorityTool(),
		service.queryMemoryTool(),
		service.addIntentTool(),
		service.addHintTool(),
	}
	return append(tools, newProjectUpdateTools(service)...)
}

func (s *Service) campaignOverviewTool() tool.BaseTool {
	return &jsonTool{
		name: "project_campaign_overview",
		desc: "查看当前批量任务的统计和资产组进度，不返回完整资产列表。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id": stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"group_limit": integerParam("最多返回资产组数，默认 10，最大 20"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID string  `json:"campaign_id"`
				GroupLimit flexInt `json:"group_limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			conversation, userID, _, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			campaignID := strings.TrimSpace(request.CampaignID)
			if campaignID == "" {
				campaignID = strings.TrimSpace(conversation.BatchID)
			}
			if campaignID == "" {
				if task, taskErr := s.db.GetCampaignTaskByConversation(
					ctx,
					conversation.ID,
					userID,
				); taskErr == nil && task != nil {
					campaignID = task.CampaignID
				}
			}
			if campaignID == "" {
				return "当前对话不属于批量任务。", nil
			}
			campaign, err := s.db.GetCampaign(ctx, campaignID, userID)
			if err != nil {
				return "", fmt.Errorf("读取批量任务失败: %w", err)
			}
			status, err := s.db.CampaignSummary(ctx, campaignID)
			if err != nil {
				return "", fmt.Errorf("读取批量任务状态失败: %w", err)
			}
			groups, err := s.db.ListCampaignGroups(ctx, campaignID)
			if err != nil {
				return "", fmt.Errorf("读取资产组失败: %w", err)
			}
			limit := clampProjectLimit(int(request.GroupLimit), 10)
			var builder strings.Builder
			builder.WriteString(fmt.Sprintf("批量任务：%s（%s）\n", campaign.Title, status.Status))
			builder.WriteString(fmt.Sprintf(
				"资产组 %d，资产 %d，Endpoint %d，任务 queued/running/completed/failed/paused = %d/%d/%d/%d/%d\n",
				status.TotalGroups,
				status.TotalAssets,
				status.TotalEndpoints,
				status.QueuedTasks,
				status.RunningTasks,
				status.CompletedTasks,
				status.FailedTasks,
				status.PausedTasks,
			))
			builder.WriteString(fmt.Sprintf(
				"覆盖率：%d/%d\n",
				status.CoverageCompleted,
				status.CoverageTotal,
			))
			builder.WriteString("资产组进度：\n")
			for index, group := range groups {
				if index >= limit {
					builder.WriteString(fmt.Sprintf("- …（另有 %d 个资产组）\n", len(groups)-limit))
					break
				}
				builder.WriteString(fmt.Sprintf(
					"- %s：%d/%d 完成，失败 %d（%s）\n",
					group.Label,
					group.CompletedAssets,
					group.TotalAssets,
					group.FailedAssets,
					group.Status,
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) campaignFrontierTool() tool.BaseTool {
	return &jsonTool{
		name: "project_campaign_frontier",
		desc: "查看 Campaign Frontier 中优先级最高的待执行任务。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id": stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"limit":       integerParam("返回条数，默认 20，最大 100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID string  `json:"campaign_id"`
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
			items, err := s.db.ListCampaignFrontier(ctx, campaignID, limit)
			if err != nil {
				return "", fmt.Errorf("读取 Frontier 失败: %w", err)
			}
			if len(items) == 0 {
				return "Campaign Frontier 暂无任务。", nil
			}
			var builder strings.Builder
			for _, item := range items {
				builder.WriteString(fmt.Sprintf(
					"- [%d/%s] %s asset=%s reason=%s source=%s id=%s\n",
					item.Priority,
					item.Status,
					item.Kind,
					item.AssetID,
					item.Reason,
					item.SourceRef,
					item.ID,
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) planFrontierTool() tool.BaseTool {
	return &jsonTool{
		name: "project_plan_frontier",
		desc: "Planner 写入结构化 Frontier 候选任务，供 Campaign 调度器按优先级执行。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id": stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"items_json": stringParam(
				`JSON 数组，例如 [{"asset_id":"...","kind":"verify_finding","intent":"...","priority":90,"reason":"...","dedupe_key":"...","source_type":"finding","source_ref":"..."}]`,
				true,
			),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID string `json:"campaign_id"`
				ItemsJSON  string `json:"items_json"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, userID, projectID, err := s.currentCampaign(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "", fmt.Errorf("当前对话不属于批量任务")
			}
			campaign, err := s.db.GetCampaign(ctx, campaignID, userID)
			if err != nil {
				return "", err
			}
			var inputs []struct {
				AssetID    string  `json:"asset_id"`
				Kind       string  `json:"kind"`
				Intent     string  `json:"intent"`
				Priority   flexInt `json:"priority"`
				Reason     string  `json:"reason"`
				DedupeKey  string  `json:"dedupe_key"`
				SourceType string  `json:"source_type"`
				SourceRef  string  `json:"source_ref"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(request.ItemsJSON)), &inputs); err != nil {
				return "", fmt.Errorf("items_json 解析失败: %w", err)
			}
			if len(inputs) == 0 {
				return "", fmt.Errorf("items_json 不能为空")
			}
			if len(inputs) > 50 {
				return "", fmt.Errorf("单次最多写入 50 个 Frontier 候选")
			}
			allowedKinds := map[string]bool{
				"group_plan":       true,
				"asset_scan":       true,
				"endpoint_scan":    true,
				"verify_finding":   true,
				"credential_reuse": true,
				"pivot_test":       true,
				"reporting":        true,
			}
			created := 0
			for _, input := range inputs {
				kind := strings.ToLower(strings.TrimSpace(input.Kind))
				if !allowedKinds[kind] {
					return "", fmt.Errorf("Frontier kind 不合法: %s", input.Kind)
				}
				assetID, err := s.validateProjectAsset(
					ctx,
					projectID,
					userID,
					input.AssetID,
				)
				if err != nil {
					return "", err
				}
				if assetID == "" {
					return "", fmt.Errorf("asset_id 不能为空")
				}
				intentJSON, _ := json.Marshal(map[string]interface{}{
					"kind":   kind,
					"intent": truncateProjectText(input.Intent, projectToolLongText),
				})
				priority := int(input.Priority)
				if priority <= 0 {
					priority = 50
				}
				if _, err := s.db.EnqueueCampaignFrontier(ctx, database.CampaignFrontierItem{
					CampaignID: campaignID,
					AssetID:    assetID,
					Kind:       kind,
					Priority:   priority,
					Reason:     truncateProjectText(input.Reason, projectToolShortText),
					DedupeKey:  truncateProjectText(input.DedupeKey, projectToolShortText*2),
					SourceType: truncateProjectText(input.SourceType, projectToolShortText),
					SourceRef:  truncateProjectText(input.SourceRef, projectToolShortText*2),
					IntentJSON: string(intentJSON),
				}, database.CampaignTaskLimits{
					MaxAttempts:  campaign.MaxAttemptsPerTask,
					MaxSegments:  campaign.MaxSegmentsPerTask,
					MaxToolCalls: campaign.MaxToolCallsPerTask,
				}); err != nil {
					return "", err
				}
				created++
			}
			return fmt.Sprintf("已写入 %d 个 Frontier 候选任务。", created), nil
		},
	}
}

func (s *Service) recordLinkTool() tool.BaseTool {
	return &jsonTool{
		name: "project_record_link",
		desc: "记录两个授权资产之间的凭据复用、共享基础设施、跳板或横向关系。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id":    stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"src_asset_id":   stringParam("源资产 id", true),
			"dst_asset_id":   stringParam("目标资产 id", true),
			"kind":           stringParam("关系类型：credential_reuse/shared_infra/parent_domain/pivot/ssrf_to/lateral_move", true),
			"summary":        stringParam("关系摘要", true),
			"confidence":     integerParam("置信度 0-100"),
			"src_fact_id":    stringParam("源事实 id"),
			"src_finding_id": stringParam("源漏洞 id"),
			"evidence_refs":  stringArrayParam("证据引用；" + evidenceReferenceFormatHint),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID   string   `json:"campaign_id"`
				SrcAssetID   string   `json:"src_asset_id"`
				DstAssetID   string   `json:"dst_asset_id"`
				Kind         string   `json:"kind"`
				Summary      string   `json:"summary"`
				Confidence   flexInt  `json:"confidence"`
				SrcFactID    string   `json:"src_fact_id"`
				SrcFindingID string   `json:"src_finding_id"`
				EvidenceRefs []string `json:"evidence_refs"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, userID, projectID, err := s.currentCampaign(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "", fmt.Errorf("当前对话不属于批量任务")
			}
			srcAssetID, err := s.validateProjectAsset(ctx, projectID, userID, request.SrcAssetID)
			if err != nil {
				return "", err
			}
			dstAssetID, err := s.validateProjectAsset(ctx, projectID, userID, request.DstAssetID)
			if err != nil {
				return "", err
			}
			srcInCampaign, err := s.db.CampaignContainsAsset(ctx, campaignID, srcAssetID)
			if err != nil {
				return "", err
			}
			dstInCampaign, err := s.db.CampaignContainsAsset(ctx, campaignID, dstAssetID)
			if err != nil {
				return "", err
			}
			if !srcInCampaign || !dstInCampaign {
				return "", fmt.Errorf("跨资产关系只能连接当前 Campaign 授权范围内的资产")
			}
			link, err := s.db.CreateCampaignLink(ctx, database.CampaignLink{
				CampaignID:   campaignID,
				ProjectID:    projectID,
				SrcAssetID:   srcAssetID,
				DstAssetID:   dstAssetID,
				Kind:         strings.ToLower(strings.TrimSpace(request.Kind)),
				Summary:      truncateProjectText(request.Summary, projectToolLongText),
				Confidence:   int(request.Confidence),
				SrcFactID:    strings.TrimSpace(request.SrcFactID),
				SrcFindingID: strings.TrimSpace(request.SrcFindingID),
				EvidenceRefs: request.EvidenceRefs,
			})
			if err != nil {
				return "", err
			}
			s.refreshCampaignIntelligence(ctx, campaignID)
			return fmt.Sprintf("已记录跨资产关系：%s -> %s（%s）", link.SrcAssetID, link.DstAssetID, link.Kind), nil
		},
	}
}

func (s *Service) verifyFindingTool() tool.BaseTool {
	return &jsonTool{
		name: "project_verify_finding",
		desc: "Evidence Verifier 记录漏洞复现、不可复现、已修复或无法验证结果。",
		params: map[string]*schema.ParameterInfo{
			"campaign_id":   stringParam("批量任务 id；当前对话属于批量任务时可留空"),
			"finding_id":    stringParam("漏洞 id", true),
			"status":        stringParam("状态：pending/running/completed/failed", true),
			"result":        stringParam("验证结果", true),
			"evidence_refs": stringArrayParam("验证证据引用；" + evidenceReferenceFormatHint),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				CampaignID   string   `json:"campaign_id"`
				FindingID    string   `json:"finding_id"`
				Status       string   `json:"status"`
				Result       string   `json:"result"`
				EvidenceRefs []string `json:"evidence_refs"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			campaignID, userID, projectID, err := s.currentCampaign(ctx, request.CampaignID)
			if err != nil {
				return "", err
			}
			if campaignID == "" {
				return "", fmt.Errorf("当前对话不属于批量任务")
			}
			if _, err := s.validateProjectFindingID(
				ctx,
				projectID,
				userID,
				request.FindingID,
			); err != nil {
				return "", err
			}
			status := strings.ToLower(strings.TrimSpace(request.Status))
			switch status {
			case database.CampaignVerificationStatusPending,
				database.CampaignVerificationStatusRunning,
				database.CampaignVerificationStatusCompleted,
				database.CampaignVerificationStatusFailed:
			default:
				return "", fmt.Errorf("验证状态不合法")
			}
			item, err := s.db.UpsertCampaignVerification(ctx, database.CampaignVerification{
				CampaignID:   campaignID,
				FindingID:    request.FindingID,
				TaskID:       execctx.CampaignTaskID(ctx),
				Status:       status,
				Result:       truncateProjectText(request.Result, projectToolLongText),
				EvidenceRefs: request.EvidenceRefs,
			})
			if err != nil {
				return "", err
			}
			s.refreshCampaignIntelligence(ctx, campaignID)
			return fmt.Sprintf("漏洞验证已记录：finding=%s status=%s attempts=%d", item.FindingID, item.Status, item.Attempts), nil
		},
	}
}

// nextTargetsTool 按覆盖率优先级返回最值得继续测试的目标，驱动 Agent 自取未覆盖队列。
func (s *Service) nextTargetsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_next_targets",
		desc: "按覆盖率优先级返回当前项目最值得继续测试的目标；最近已探测但未闭环的资产会明确标记，提示先写回结果。",
		params: map[string]*schema.ParameterInfo{
			"limit": integerParam("返回条数，默认 10，最大 20"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Limit flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			coverage, err := s.db.ProjectCoverage(ctx, projectID, userID)
			if err != nil {
				return "", fmt.Errorf("读取覆盖率失败: %w", err)
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 20 {
				limit = 10
			}
			var builder strings.Builder
			builder.WriteString(fmt.Sprintf(
				"资产观测覆盖 %d/%d（%.0f%%），完整覆盖 %d/%d（%.0f%%），部分覆盖 %d，阻断 %d，可疑 %d，未测试 %d，测试覆盖 %d/%d（%.0f%%），必需/可选未完成测试 %d/%d，可疑测试 %d，证据缺口 %d，待办/运行意图 %d/%d\n",
				coverage.AssetsTested,
				coverage.AssetsTotal,
				coverage.CoverageRatio*100,
				coverage.AssetsCovered,
				coverage.AssetsTotal,
				coverage.FullCoverageRatio*100,
				coverage.AssetsPartial,
				coverage.AssetsBlocked,
				coverage.AssetsSuspicious,
				coverage.AssetsUntested,
				coverage.TestsCovered,
				coverage.TestsTotal,
				coverage.TestCoverageRatio*100,
				coverage.TestsOpenRequired,
				coverage.TestsOpenOptional,
				coverage.TestsSuspicious,
				coverage.FactsWithoutEvidence+coverage.FindingsWithoutEvidence,
				coverage.IntentsOpen,
				coverage.IntentsRunning,
			))
			if len(coverage.NextTargets) == 0 {
				builder.WriteString("未覆盖队列：无\n")
				return strings.TrimSpace(builder.String()), nil
			}
			builder.WriteString("未覆盖队列（优先级从高到低）：\n")
			assetID := currentAssetID(ctx)
			probeHosts := s.recentProbeHosts(ctx, currentConversationID(ctx))
			for index, target := range coverage.NextTargets {
				if index >= limit {
					break
				}
				if assetID != "" && target.Kind == "asset" && target.RefID != assetID {
					continue
				}
				reason := target.Reason
				if target.Kind == "asset" {
					reason += recentProbeAnnotation(target.Label, probeHosts)
				}
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s — %s（ref=%s，优先级 %d）\n",
					target.Kind,
					target.Label,
					reason,
					target.RefID,
					target.Score,
				))
			}
			return strings.TrimSpace(builder.String()), nil
		},
	}
}

func (s *Service) recordTestResultTool() tool.BaseTool {
	return &jsonTool{
		name: "project_record_test",
		desc: "记录单个资产的安全测试覆盖结果；负向结论必须提供 evidence_refs，确认漏洞必须关联 finding。",
		params: map[string]*schema.ParameterInfo{
			"asset_id":      stringParam("资产 id（必须是本项目资产）", true),
			"dimension":     stringParam("测试维度，例如 SQL注入、XSS、认证", true),
			"technique":     stringParam("测试技术，例如 boolean/error/union/time-based"),
			"status":        stringParam("状态：untested/running/tested_clean/blocked/suspicious/confirmed", true),
			"result":        stringParam("测试结论或负向结果"),
			"evidence":      stringParam("证据摘要"),
			"evidence_refs": stringArrayParam("证据引用数组；" + evidenceReferenceFormatHint),
			"confidence":    integerParam("置信度 0-100"),
			"finding_id":    stringParam("confirmed 结果关联的漏洞 id"),
			"intent_id":     stringParam("关联攻击意图 id"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetID      string   `json:"asset_id"`
				Dimension    string   `json:"dimension"`
				Technique    string   `json:"technique"`
				Status       string   `json:"status"`
				Result       string   `json:"result"`
				Evidence     string   `json:"evidence"`
				EvidenceRefs []string `json:"evidence_refs"`
				Confidence   flexInt  `json:"confidence"`
				FindingID    string   `json:"finding_id"`
				IntentID     string   `json:"intent_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			assetID, err := s.validateProjectAsset(
				ctx,
				projectID,
				userID,
				request.AssetID,
			)
			if err != nil {
				return "", err
			}
			if assetID == "" {
				return "", fmt.Errorf("asset_id 不能为空")
			}
			dimension := truncateProjectText(request.Dimension, projectToolShortText)
			if dimension == "" {
				return "", fmt.Errorf("dimension 不能为空")
			}
			status, ok := database.NormalizeProjectTestResultStatus(request.Status)
			if !ok {
				return "", fmt.Errorf("测试状态不合法")
			}
			result := truncateProjectText(request.Result, projectToolLongText)
			evidence := truncateProjectText(request.Evidence, projectToolLongText)
			evidenceRefs := append([]string(nil), request.EvidenceRefs...)
			switch status {
			case "tested_clean":
				if result == "" || (evidence == "" && len(evidenceRefs) == 0) {
					return "", fmt.Errorf("tested_clean 必须提供测试结论和证据")
				}
			case "suspicious":
				if result == "" {
					return "", fmt.Errorf("suspicious 必须提供测试结论")
				}
			case "confirmed":
				if strings.TrimSpace(request.FindingID) == "" {
					return "", fmt.Errorf("confirmed 测试必须关联 finding_id")
				}
				if evidence == "" && len(evidenceRefs) == 0 {
					return "", fmt.Errorf("confirmed 测试必须提供证据")
				}
				if _, err := s.validateProjectFindingID(ctx, projectID, userID, request.FindingID); err != nil {
					return "", err
				}
				if err := s.validateProjectIntentID(ctx, projectID, request.IntentID); err != nil {
					return "", err
				}
				if err := s.validateEvidenceReferences(ctx, projectID, userID, evidenceRefs, "high"); err != nil {
					return "", err
				}
			case "blocked":
				if result == "" {
					return "", fmt.Errorf("blocked 必须说明阻断原因")
				}
			}
			confidence := int(request.Confidence)
			if confidence < 0 {
				confidence = 0
			}
			if confidence > 100 {
				confidence = 100
			}
			saved, err := s.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
				ProjectID:    projectID,
				AssetID:      assetID,
				Dimension:    dimension,
				Technique:    truncateProjectText(request.Technique, projectToolShortText),
				Status:       status,
				Result:       result,
				Evidence:     evidence,
				EvidenceRefs: evidenceRefs,
				Confidence:   confidence,
				FindingID:    strings.TrimSpace(request.FindingID),
				IntentID:     strings.TrimSpace(request.IntentID),
				CreatedAt:    time.Now().UTC(),
			})
			if err != nil {
				return "", fmt.Errorf("记录测试结果失败: %w", err)
			}
			if campaignID := strings.TrimSpace(execctx.CampaignID(ctx)); campaignID != "" {
				if err := s.db.UpsertCampaignCoverage(
					ctx,
					campaignID,
					assetID,
					dimension,
					strings.TrimSpace(request.Technique),
					status,
					evidenceRefs,
				); err != nil {
					return "", fmt.Errorf("更新 Campaign 覆盖率失败: %w", err)
				}
			}
			return fmt.Sprintf(
				"已记录测试结果：%s / %s，状态 %s，置信度 %d（id %s）",
				saved.Dimension,
				orDefaultProjectToolValue(saved.Technique, "-"),
				saved.Status,
				saved.Confidence,
				saved.ID,
			), nil
		},
	}
}

func orDefaultProjectToolValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func currentAssetID(ctx context.Context) string {
	return strings.TrimSpace(execctx.AssetID(ctx))
}

func graphNodeInCurrentAssetScope(ctx context.Context, node *database.GraphNode) bool {
	if node == nil {
		return false
	}
	assetID := currentAssetID(ctx)
	return assetID == "" || node.AssetID == "" || node.AssetID == assetID
}

func assetIDFromFactRelation(relation string) string {
	lower := strings.ToLower(relation)
	index := strings.Index(lower, "asset:")
	if index < 0 {
		return ""
	}
	value := relation[index+len("asset:"):]
	end := strings.IndexAny(value, ",; \t\r\n")
	if end >= 0 {
		value = value[:end]
	}
	return strings.TrimSpace(value)
}

func (s *Service) projectListTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list",
		desc: `统一查询当前项目的列表数据。resource 可选 facts、assets、findings、hypotheses、entities、chains；query 用于匹配名称、标题、键值或摘要；summary 默认 10 条并限制 3000 字符，detail 默认 20 条并放宽到 6000 字符。`,
		params: map[string]*schema.ParameterInfo{
			"resource": stringEnumParam(
				"要查询的数据类型",
				[]string{"facts", "assets", "findings", "hypotheses", "entities", "chains"},
				true,
			),
			"query":       stringParam("按名称、标题、键值、目标或摘要搜索"),
			"asset_id":    stringParam("资产 id，适用于 facts/findings；留空时使用当前会话资产"),
			"status":      stringParam("状态过滤，适用于 assets/findings/hypotheses/chains"),
			"severity":    stringParam("严重度过滤，仅适用于 findings"),
			"kind":        stringParam("类型过滤，适用于 facts/assets/entities/chains"),
			"campaign_id": stringParam("批量任务 id，仅适用于 chains；可留空使用当前批量任务"),
			"limit":       integerParam("返回条数；summary 默认 10，detail 默认 20；facts/assets/findings 最大 50，hypotheses/chains 最大 100，entities 最大 200"),
			"view": stringEnumParam(
				"输出详细程度",
				[]string{"summary", "detail"},
			),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Resource   string  `json:"resource"`
				Query      string  `json:"query"`
				Name       string  `json:"name"`
				AssetID    string  `json:"asset_id"`
				Status     string  `json:"status"`
				Severity   string  `json:"severity"`
				Kind       string  `json:"kind"`
				CampaignID string  `json:"campaign_id"`
				Limit      flexInt `json:"limit"`
				Size       flexInt `json:"size"`
				View       string  `json:"view"`
			}
			if err := decodeProjectReadToolArgs(raw, &request); err != nil {
				return "", err
			}
			resource := strings.ToLower(strings.TrimSpace(request.Resource))
			if err := authorizeProjectReadResource(ctx, "project_list", resource); err != nil {
				return "", err
			}
			if err := validateProjectListParams(resource, request.AssetID, request.Status, request.Severity, request.Kind, request.CampaignID); err != nil {
				return "", err
			}
			view := strings.ToLower(strings.TrimSpace(request.View))
			if view == "" {
				view = "summary"
			}
			if view != "summary" && view != "detail" {
				return "", fmt.Errorf("view 仅支持 summary 或 detail")
			}
			requestedLimit := int(request.Limit)
			if requestedLimit == 0 {
				requestedLimit = int(request.Size)
			}
			limit := projectListLimit(resource, requestedLimit, view)
			query := strings.TrimSpace(request.Query)
			if query == "" {
				query = strings.TrimSpace(request.Name)
			}
			payload := map[string]interface{}{
				"limit": limit,
				"query": query,
			}
			var legacy tool.BaseTool
			switch resource {
			case "facts":
				payload["asset_id"] = strings.TrimSpace(request.AssetID)
				payload["kind"] = strings.TrimSpace(request.Kind)
				legacy = s.listFactsTool()
			case "assets":
				payload["kind"] = strings.TrimSpace(request.Kind)
				payload["status"] = strings.TrimSpace(request.Status)
				legacy = s.listAssetsTool()
			case "findings":
				payload["asset_id"] = strings.TrimSpace(request.AssetID)
				payload["status"] = strings.TrimSpace(request.Status)
				payload["severity"] = strings.TrimSpace(request.Severity)
				legacy = s.listFindingsTool()
			case "hypotheses":
				payload["status"] = strings.TrimSpace(request.Status)
				legacy = s.listHypothesesTool()
			case "entities":
				payload["entity_type"] = strings.TrimSpace(request.Kind)
				legacy = s.listMemoryEntitiesTool()
			case "chains":
				payload["campaign_id"] = strings.TrimSpace(request.CampaignID)
				payload["status"] = strings.TrimSpace(request.Status)
				payload["kind"] = strings.TrimSpace(request.Kind)
				legacy = s.listChainsTool()
			}
			invokable, ok := legacy.(tool.InvokableTool)
			if !ok {
				return "", fmt.Errorf("列表资源 %s 暂不可用", resource)
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				return "", err
			}
			result, err := invokable.InvokableRun(ctx, string(encoded))
			if err != nil {
				return "", err
			}
			if view == "summary" {
				return truncateProjectText(result, 3000), nil
			}
			return result, nil
		},
	}
}

func (s *Service) projectGetTool() tool.BaseTool {
	return &jsonTool{
		name: "project_get",
		desc: "按 ID 读取单个项目对象详情。resource 可选 asset、finding、graph_node；id 为对象 ID，asset 留空时使用当前会话绑定资产。",
		params: map[string]*schema.ParameterInfo{
			"resource": stringEnumParam(
				"要读取的对象类型",
				[]string{"asset", "finding", "graph_node"},
				true,
			),
			"id": stringParam("对象 ID；asset 可留空使用当前会话资产"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Resource  string `json:"resource"`
				ID        string `json:"id"`
				AssetID   string `json:"asset_id"`
				FindingID string `json:"finding_id"`
				NodeID    string `json:"node_id"`
			}
			if err := decodeProjectReadToolArgs(raw, &request); err != nil {
				return "", err
			}
			resource := strings.ToLower(strings.TrimSpace(request.Resource))
			if err := authorizeProjectReadResource(ctx, "project_get", resource); err != nil {
				return "", err
			}
			if err := validateProjectGetParams(
				resource,
				request.ID,
				request.AssetID,
				request.FindingID,
				request.NodeID,
			); err != nil {
				return "", err
			}
			id := firstNonEmpty(request.ID, request.AssetID, request.FindingID, request.NodeID)
			if resource != "asset" && id == "" {
				return "", fmt.Errorf("resource=%s 的 id 不能为空", resource)
			}
			payload := map[string]interface{}{}
			var legacy tool.BaseTool
			switch resource {
			case "asset":
				payload["asset_id"] = id
				legacy = s.assetCardTool()
			case "finding":
				payload["finding_id"] = id
				legacy = s.getFindingTool()
			case "graph_node":
				payload["node_id"] = id
				legacy = s.graphNodeTool()
			default:
				return "", fmt.Errorf("resource 必须是 asset、finding 或 graph_node")
			}
			invokable, ok := legacy.(tool.InvokableTool)
			if !ok {
				return "", fmt.Errorf("详情资源 %s 暂不可用", resource)
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				return "", err
			}
			return invokable.InvokableRun(ctx, string(encoded))
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func validateProjectGetParams(resource string, id string, assetID string, findingID string, nodeID string) error {
	invalid := func(name string) error {
		return fmt.Errorf("resource=%s 不支持参数 %s", resource, name)
	}
	aliasName := ""
	aliasValue := ""
	switch resource {
	case "asset":
		if strings.TrimSpace(findingID) != "" {
			return invalid("finding_id")
		}
		if strings.TrimSpace(nodeID) != "" {
			return invalid("node_id")
		}
		aliasName, aliasValue = "asset_id", assetID
	case "finding":
		if strings.TrimSpace(assetID) != "" {
			return invalid("asset_id")
		}
		if strings.TrimSpace(nodeID) != "" {
			return invalid("node_id")
		}
		aliasName, aliasValue = "finding_id", findingID
	case "graph_node":
		if strings.TrimSpace(assetID) != "" {
			return invalid("asset_id")
		}
		if strings.TrimSpace(findingID) != "" {
			return invalid("finding_id")
		}
		aliasName, aliasValue = "node_id", nodeID
	default:
		return fmt.Errorf("resource 必须是 asset、finding 或 graph_node")
	}
	if strings.TrimSpace(id) != "" &&
		strings.TrimSpace(aliasValue) != "" &&
		strings.TrimSpace(id) != strings.TrimSpace(aliasValue) {
		return fmt.Errorf("id 与 %s 冲突", aliasName)
	}
	return nil
}

func validateProjectListParams(
	resource string,
	assetID string,
	status string,
	severity string,
	kind string,
	campaignID string,
) error {
	assetID = strings.TrimSpace(assetID)
	status = strings.TrimSpace(status)
	severity = strings.TrimSpace(severity)
	kind = strings.TrimSpace(kind)
	campaignID = strings.TrimSpace(campaignID)
	invalid := func(name string) error {
		return fmt.Errorf("resource=%s 不支持参数 %s", resource, name)
	}
	switch resource {
	case "facts":
		if status != "" {
			return invalid("status")
		}
		if severity != "" {
			return invalid("severity")
		}
		if campaignID != "" {
			return invalid("campaign_id")
		}
	case "assets":
		if assetID != "" {
			return invalid("asset_id")
		}
		if severity != "" {
			return invalid("severity")
		}
		if campaignID != "" {
			return invalid("campaign_id")
		}
	case "findings":
		if kind != "" {
			return invalid("kind")
		}
		if campaignID != "" {
			return invalid("campaign_id")
		}
	case "hypotheses":
		if assetID != "" {
			return invalid("asset_id")
		}
		if severity != "" {
			return invalid("severity")
		}
		if kind != "" {
			return invalid("kind")
		}
		if campaignID != "" {
			return invalid("campaign_id")
		}
	case "entities":
		if assetID != "" {
			return invalid("asset_id")
		}
		if status != "" {
			return invalid("status")
		}
		if severity != "" {
			return invalid("severity")
		}
		if campaignID != "" {
			return invalid("campaign_id")
		}
	case "chains":
		if assetID != "" {
			return invalid("asset_id")
		}
		if severity != "" {
			return invalid("severity")
		}
	default:
		return fmt.Errorf("resource 必须是 facts、assets、findings、hypotheses、entities 或 chains")
	}
	return nil
}

func decodeProjectReadToolArgs(raw string, target interface{}) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		trimmed = "{}"
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("解析工具参数失败: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("工具参数只能包含一个 JSON 对象")
		}
		return fmt.Errorf("解析工具参数失败: %w", err)
	}
	return nil
}

func projectListLimit(resource string, requested int, view string) int {
	maximum := projectToolListLimit
	switch resource {
	case "hypotheses", "chains":
		maximum = 100
	case "entities":
		maximum = 200
	}
	if requested <= 0 {
		requested = 10
		if view == "detail" {
			requested = 20
		}
	}
	if requested > maximum {
		return maximum
	}
	return requested
}

func legacyProjectListResource(name string) (string, bool) {
	switch strings.TrimSpace(name) {
	case "project_list_facts":
		return "facts", true
	case "project_list_assets":
		return "assets", true
	case "project_list_findings":
		return "findings", true
	case "project_list_hypotheses":
		return "hypotheses", true
	case "project_list_entities":
		return "entities", true
	case "project_list_chains":
		return "chains", true
	default:
		return "", false
	}
}

func legacyProjectListToolName(resource string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "facts":
		return "project_list_facts", true
	case "assets":
		return "project_list_assets", true
	case "findings":
		return "project_list_findings", true
	case "hypotheses":
		return "project_list_hypotheses", true
	case "entities":
		return "project_list_entities", true
	case "chains":
		return "project_list_chains", true
	default:
		return "", false
	}
}

func legacyProjectGetResource(name string) (string, bool) {
	switch strings.TrimSpace(name) {
	case "project_asset_card":
		return "asset", true
	case "project_get_finding":
		return "finding", true
	case "project_graph_node":
		return "graph_node", true
	default:
		return "", false
	}
}

func legacyProjectGetToolName(resource string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "asset":
		return "project_asset_card", true
	case "finding":
		return "project_get_finding", true
	case "graph_node":
		return "project_graph_node", true
	default:
		return "", false
	}
}

func (s *Service) listFactsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_facts",
		desc: "列出当前资产及项目级公共事实；未指定 asset_id 时使用当前对话绑定资产。",
		params: map[string]*schema.ParameterInfo{
			"asset_id": stringParam("资产 id；留空时使用当前对话绑定资产"),
			"query":    stringParam("按键、类型、摘要或值搜索"),
			"kind":     stringParam("按事实类型过滤"),
			"limit":    integerParam("返回条数，默认 20，最大 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetID string  `json:"asset_id"`
				Query   string  `json:"query"`
				Kind    string  `json:"kind"`
				Limit   flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			assetID := strings.TrimSpace(request.AssetID)
			if assetID == "" {
				assetID = currentAssetID(ctx)
			}
			if assetID != "" {
				assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
				if err != nil {
					return "", err
				}
			}
			items, err := s.db.ListProjectFactsByAsset(ctx, projectID, assetID)
			if err != nil {
				return "", fmt.Errorf("读取项目事实失败: %w", err)
			}
			limit := clampProjectLimit(int(request.Limit), 20)
			query := strings.ToLower(strings.TrimSpace(request.Query))
			kind := strings.ToLower(strings.TrimSpace(request.Kind))
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if kind != "" && strings.ToLower(item.FactType) != kind {
					continue
				}
				if query != "" && !projectTextMatches(query, item.Key, item.FactType, item.Value, projectFactSummary(item), item.ID, item.AssetID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				extra := ""
				if relation := strings.TrimSpace(item.Relation); relation != "" {
					extra += fmt.Sprintf("，relation=%s", relation)
				}
				if strings.TrimSpace(item.Evidence) != "" {
					extra += "，evidence=已记录"
				}
				extra += fmt.Sprintf("，kind=%s，priority=%d", orDefaultProjectToolValue(item.MemoryKind, "general"), item.Priority)
				if item.Pinned {
					extra += "，pinned=true"
				}
				if item.ContradictedBy != "" {
					extra += "，conflict=" + item.ContradictedBy
				}
				if item.AssetID != "" {
					extra += fmt.Sprintf("，asset=%s", item.AssetID)
				} else {
					extra += "，scope=project"
				}
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s: %s（置信度 %d%s）\n",
					item.FactType,
					item.Key,
					projectFactSummary(item),
					item.Confidence,
					extra,
				))
			}
			if builder.Len() == 0 {
				return "当前项目还没有记录任何事实。", nil
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) recordFactTool() tool.BaseTool {
	return &jsonTool{
		name: "project_record_fact",
		desc: "把已确认的环境认知、攻击链上下文或否定结论按稳定 category/slug key 幂等写入；禁止写 test_result 和 finding，测试用 project_record_test，漏洞用 project_report_finding。",
		params: map[string]*schema.ParameterInfo{
			"asset_id":     stringParam("所属资产 id；留空时使用当前对话绑定资产"),
			"intent_id":    stringParam("产生本事实的 intent id，用于建立探索链路"),
			"key":          stringParam("事实标识，例如 目标IP、WAF类型", true),
			"summary":      stringParam("一行摘要：什么 + 在哪 + 如何验证", true),
			"body":         stringParam("完整可复现上下文、步骤和原始信息"),
			"evidence":     stringParam("支持该事实的证据或证据来源"),
			"relation":     stringParam("关联引用，例如 asset:<id>、fact:<key>、finding:<id>"),
			"fact_type":    stringParam("事实分类，默认 general"),
			"confidence":   integerParam("置信度 0-100，默认 80"),
			"value":        stringParam("兼容旧调用；summary 为空时作为摘要"),
			"supersedes":   stringParam("可选：本次事实取代的旧事实 key，将旧记忆标记为失效"),
			"memory_kind":  stringParam("记忆类型：scope/credential/asset/finding/topology/constraint/general"),
			"priority":     integerParam("记忆优先级 0-100"),
			"pinned":       stringParam("是否固定注入，true/false"),
			"observed_at":  integerParam("观测时间 Unix 秒，可选"),
			"subject_type": stringParam("结构化主体类型，例如 asset/service/endpoint/credential"),
			"subject_key":  stringParam("结构化主体标识"),
			"predicate":    stringParam("结构化谓词，例如 version/status/exposes"),
			"object_type":  stringParam("结构化对象类型"),
			"object_key":   stringParam("结构化对象标识或值"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetID     string  `json:"asset_id"`
				IntentID    string  `json:"intent_id"`
				Key         string  `json:"key"`
				Value       string  `json:"value"`
				Summary     string  `json:"summary"`
				Body        string  `json:"body"`
				Evidence    string  `json:"evidence"`
				Relation    string  `json:"relation"`
				FactType    string  `json:"fact_type"`
				Confidence  flexInt `json:"confidence"`
				Supersedes  string  `json:"supersedes"`
				MemoryKind  string  `json:"memory_kind"`
				Priority    flexInt `json:"priority"`
				Pinned      string  `json:"pinned"`
				ObservedAt  flexInt `json:"observed_at"`
				SubjectType string  `json:"subject_type"`
				SubjectKey  string  `json:"subject_key"`
				Predicate   string  `json:"predicate"`
				ObjectType  string  `json:"object_type"`
				ObjectKey   string  `json:"object_key"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			assetID := strings.TrimSpace(request.AssetID)
			if assetID == "" {
				assetID = currentAssetID(ctx)
			}
			if assetID == "" {
				assetID = assetIDFromFactRelation(request.Relation)
			}
			if assetID != "" {
				assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
				if err != nil {
					return "", err
				}
			}
			if err := s.validateCampaignAssetScope(ctx, assetID); err != nil {
				return "", err
			}
			intentID := strings.TrimSpace(request.IntentID)
			intentWarning := ""
			if intentID != "" {
				intentNode, loadErr := s.db.GetProjectGraphNode(ctx, intentID, projectID)
				if errors.Is(loadErr, sql.ErrNoRows) ||
					(loadErr == nil && (intentNode == nil || intentNode.Kind != "intent")) {
					intentWarning = fmt.Sprintf("；intent_id %s 不存在，事实已写入但未关联 intent", intentID)
					intentID = ""
				} else if loadErr != nil {
					return "", fmt.Errorf("读取 intent 节点失败: %w", loadErr)
				} else if !graphAssetScopeCompatible(assetID, intentNode.AssetID) {
					return "", fmt.Errorf("intent_id 与事实不属于同一资产")
				}
			}
			factType := strings.ToLower(strings.TrimSpace(request.FactType))
			if factType == "" {
				factType = "general"
			}
			memoryKind := strings.ToLower(strings.TrimSpace(request.MemoryKind))
			subjectType := strings.ToLower(strings.TrimSpace(request.SubjectType))
			if strings.HasPrefix(subjectType, "audit_") {
				return "", fmt.Errorf("审计范围、矩阵和断点必须使用 project_record_audit 写入")
			}
			if factType == "test_result" || memoryKind == "test_result" {
				return "", fmt.Errorf("测试结果请调用 project_record_test，不要写入事实库；事实只保存环境认知、攻击链上下文和否定结论")
			}
			if factType == "finding" || memoryKind == "finding" {
				return "", fmt.Errorf("可交付漏洞请调用 project_report_finding；攻击链上下文请使用 chain/exploit/poc 前缀的 fact key")
			}
			key, err := normalizeProjectFactKey(request.Key, factType, memoryKind)
			if err != nil {
				return "", err
			}
			if key == "business/audit-scope" ||
				strings.HasPrefix(key, "business/audit-cell-") ||
				strings.HasPrefix(key, "note/round-checkpoint-") {
				return "", fmt.Errorf("审计范围、矩阵和断点必须使用 project_record_audit 写入")
			}
			summary := strings.TrimSpace(request.Summary)
			if summary == "" {
				summary = strings.TrimSpace(request.Value)
			}
			summary = truncateProjectText(summary, projectToolShortText)
			if key == "" || summary == "" {
				return "", fmt.Errorf("key 与 summary 不能为空")
			}
			confidence := int(request.Confidence)
			if confidence <= 0 {
				confidence = 80
			}
			if confidence > 100 {
				confidence = 100
			}
			now := time.Now().UTC()
			priority := int(request.Priority)
			if priority <= 0 {
				priority = confidence
			}
			if priority > 100 {
				priority = 100
			}
			observedAt := now
			if request.ObservedAt > 0 {
				observedAt = time.Unix(int64(request.ObservedAt), 0).UTC()
			}
			if strings.TrimSpace(request.Supersedes) == "" {
				if conflict, conflictErr := s.findConclusionConflict(ctx, projectID, database.ProjectFact{
					ProjectID:  projectID,
					AssetID:    assetID,
					FactType:   factType,
					Key:        key,
					Summary:    summary,
					Confidence: confidence,
				}); conflictErr == nil && conflict != nil {
					return "", &factConclusionConflictError{Fact: conflict, Key: key}
				}
			}
			decision, err := s.consolidateFact(ctx, projectID, database.ProjectFact{
				ID:        randomID(),
				ProjectID: projectID,
				AssetID:   assetID,
				FactType:  factType,
				Key:       key,
				Value:     summary,
				Summary:   summary,
				Body:      truncateProjectText(request.Body, projectToolLongText),
				Evidence:  truncateProjectText(request.Evidence, projectToolLongText),
				Relation: appendFactIntentRelation(
					truncateProjectText(request.Relation, projectToolShortText),
					intentID,
				),
				Confidence:  confidence,
				SourceType:  "conversation",
				SourceID:    execctx.ConversationID(ctx),
				Importance:  importanceFromConfidence(confidence),
				MemoryKind:  memoryKind,
				Priority:    priority,
				Pinned:      strings.EqualFold(strings.TrimSpace(request.Pinned), "true"),
				ObservedAt:  observedAt,
				SubjectType: subjectType,
				SubjectKey:  strings.TrimSpace(request.SubjectKey),
				Predicate:   strings.TrimSpace(request.Predicate),
				ObjectType:  strings.TrimSpace(request.ObjectType),
				ObjectKey:   strings.TrimSpace(request.ObjectKey),
				CreatedAt:   now,
				UpdatedAt:   now,
			})
			if err != nil {
				return "", fmt.Errorf("写入项目事实失败: %w", err)
			}
			if strings.TrimSpace(request.Supersedes) != "" {
				if err := s.supersedeFact(ctx, projectID, assetID, request.Supersedes, decision.Fact); err != nil {
					return "", fmt.Errorf("失效旧事实失败: %w", err)
				}
			}
			saved := decision.Fact
			if saved == nil {
				return "", fmt.Errorf("写入项目事实失败: 结果为空")
			}
			reuseTasks := 0
			if campaignID, campaignErr := s.resolveCampaignID(ctx, ""); campaignErr == nil && campaignID != "" {
				if isCredentialFact(*saved) {
					reuseTasks, _ = s.db.EnqueueCredentialReuseTasks(
						ctx,
						campaignID,
						saved.AssetID,
						saved.ID,
						saved.Summary,
					)
				}
				s.refreshCampaignIntelligence(ctx, campaignID)
			}
			message := fmt.Sprintf(
				"%s项目事实：%s = %s（类型 %s，置信度 %d，id %s，判定 %s）",
				memoryActionLabel(decision.Action),
				saved.Key,
				saved.Summary,
				saved.FactType,
				saved.Confidence,
				saved.ID,
				decision.Action,
			)
			if reuseTasks > 0 {
				message += fmt.Sprintf("；已入队 %d 个同组凭据复用任务", reuseTasks)
			}
			message += intentWarning
			if intentID != "" {
				factNode, linkErr := s.materializeIntentFactNode(ctx, projectID, saved)
				if linkErr != nil {
					return "", linkErr
				}
				if linkErr := s.linkGraphEdge(ctx, projectID, intentID, factNode.ID, "yields"); linkErr != nil {
					return "", linkErr
				}
				message += fmt.Sprintf("；已链接 intent %s", intentID)
			}
			s.syncProjectGraph(ctx, projectID, userID)
			return message, nil
		},
	}
}

func (s *Service) listAssetsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_assets",
		desc: "列出当前项目的资产（域名/IP/URL/端口等）。",
		params: map[string]*schema.ParameterInfo{
			"kind":   stringParam("按资产类型过滤，例如 domain/ip/url/port/host"),
			"status": stringParam("按资产状态过滤"),
			"query":  stringParam("按名称、值或类型搜索"),
			"limit":  integerParam("返回条数，默认 30，最大 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Kind   string  `json:"kind"`
				Status string  `json:"status"`
				Query  string  `json:"query"`
				Limit  flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			items, err := s.db.ListProjectAssets(ctx, projectID, userID)
			if err != nil {
				return "", fmt.Errorf("读取项目资产失败: %w", err)
			}
			kind := strings.ToLower(strings.TrimSpace(request.Kind))
			status := strings.ToLower(strings.TrimSpace(request.Status))
			query := strings.ToLower(strings.TrimSpace(request.Query))
			limit := clampProjectLimit(int(request.Limit), 30)
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if kind != "" && strings.ToLower(item.Kind) != kind {
					continue
				}
				if status != "" && strings.ToLower(item.Status) != status {
					continue
				}
				if query != "" && !projectTextMatches(query, item.Name, item.Kind, item.Value, item.Status, item.Criticality, item.ID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				builder.WriteString(fmt.Sprintf(
					"- %s（%s）value=%s status=%s criticality=%s risk=%d id=%s\n",
					item.Name,
					item.Kind,
					item.Value,
					item.Status,
					item.Criticality,
					item.RiskScore,
					item.ID,
				))
			}
			if builder.Len() == 0 {
				return "当前项目没有匹配的资产。", nil
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) insertAssetsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_insert_assets",
		desc: "批量写入当前项目资产。JSON 数组，每项包含 name/kind/value，kind 只能是 domain/ip/url/port/host，可选 criticality/risk_score/status。",
		params: map[string]*schema.ParameterInfo{
			"assets_json": stringParam(
				`JSON 数组，例如 [{"name":"主站","kind":"url","value":"https://a.com"}]`,
				true,
			),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetsJSON string `json:"assets_json"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			type assetInput struct {
				Name        string  `json:"name"`
				Kind        string  `json:"kind"`
				Value       string  `json:"value"`
				Criticality string  `json:"criticality"`
				Status      string  `json:"status"`
				RiskScore   flexInt `json:"risk_score"`
			}
			var inputs []assetInput
			if err := json.Unmarshal([]byte(strings.TrimSpace(request.AssetsJSON)), &inputs); err != nil {
				return "", fmt.Errorf("assets_json 解析失败: %w", err)
			}
			if len(inputs) == 0 {
				return "", fmt.Errorf("assets_json 不能为空数组")
			}
			if len(inputs) > 20 {
				return "", fmt.Errorf("单次最多写入 20 个资产")
			}
			for _, input := range inputs {
				kind := strings.ToLower(strings.TrimSpace(input.Kind))
				if !database.IsSupportedAssetKind(kind) {
					label := strings.TrimSpace(input.Name)
					if label == "" {
						label = strings.TrimSpace(input.Value)
					}
					if label == "" {
						label = "未命名"
					}
					return "", fmt.Errorf("资产 %s 类型 %q 不受支持，只能是 domain/ip/url/port/host", label, input.Kind)
				}
			}

			existing, err := s.db.ListProjectAssets(ctx, projectID, userID)
			if err != nil {
				return "", fmt.Errorf("读取项目资产失败: %w", err)
			}
			seen := make(map[string]bool, len(existing))
			for _, item := range existing {
				seen[assetKey(item.Kind, item.Value)] = true
			}

			var builder strings.Builder
			created := 0
			skipped := 0
			now := time.Now().UTC()
			for _, input := range inputs {
				value := truncateProjectText(input.Value, projectToolShortText*2)
				if value == "" {
					skipped++
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(input.Kind))
				dedupKey := assetKey(kind, value)
				if seen[dedupKey] {
					skipped++
					continue
				}
				seen[dedupKey] = true
				name := truncateProjectText(input.Name, projectToolShortText)
				if name == "" {
					name = value
				}
				status := strings.TrimSpace(input.Status)
				if status == "" {
					status = "active"
				}
				criticality := strings.TrimSpace(input.Criticality)
				if criticality == "" {
					criticality = "medium"
				}
				riskScore := int(input.RiskScore)
				if riskScore < 0 {
					riskScore = 0
				}
				if riskScore > 100 {
					riskScore = 100
				}
				item := database.Asset{
					ID:          randomID(),
					ProjectID:   projectID,
					OwnerUserID: userID,
					Name:        name,
					Kind:        kind,
					Value:       value,
					Status:      status,
					Criticality: criticality,
					RiskScore:   riskScore,
					CreatedAt:   now,
					UpdatedAt:   now,
				}
				if err := s.db.CreateAsset(ctx, item); err != nil {
					return "", fmt.Errorf("写入资产 %s 失败: %w", value, err)
				}
				created++
				builder.WriteString(fmt.Sprintf("- 已写入 %s（%s，id %s）\n", value, kind, item.ID))
			}
			builder.WriteString(fmt.Sprintf("共写入 %d 个资产，跳过 %d 个（重复或空值）。", created, skipped))
			s.syncProjectGraph(ctx, projectID, userID)
			return capProjectOutput(&builder), nil
		},
	}
}

func validateStandardFindingReport(item database.Vulnerability) error {
	severity := strings.ToLower(strings.TrimSpace(item.Severity))
	if severity != "critical" && severity != "high" && severity != "medium" {
		return nil
	}
	required := []struct {
		label string
		value string
	}{
		{label: "description", value: item.Description},
		{label: "preconditions", value: item.Preconditions},
		{label: "poc", value: item.ReproductionSteps},
		{label: "evidence", value: item.Evidence},
		{label: "impact", value: item.Impact},
		{label: "recommendation", value: item.Recommendation},
		{label: "residual_notes", value: item.RetestNotes},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s 漏洞必须提供完整的 %s 字段", severity, field.label)
		}
	}
	poc := strings.TrimSpace(item.ReproductionSteps)
	hasStructuredPOC := strings.Contains(poc, "```") ||
		strings.Contains(poc, "curl ") ||
		strings.Contains(poc, "GET ") ||
		strings.Contains(poc, "POST ") ||
		strings.Contains(poc, "PUT ") ||
		strings.Contains(poc, "PATCH ") ||
		strings.Contains(poc, "DELETE ") ||
		strings.Contains(poc, "http://") ||
		strings.Contains(poc, "https://")
	if !hasStructuredPOC || len([]rune(poc)) < 20 {
		return fmt.Errorf("%s 漏洞必须提供完整 PoC、HTTP 数据包或可复现步骤", severity)
	}
	return nil
}

func (s *Service) reportFindingTool() tool.BaseTool {
	return &jsonTool{
		name: "project_report_finding",
		desc: "把已确认漏洞按平台标准上报。标题由系统按“项目-系统地址-漏洞地址-类型-危害-编号”生成；漏洞类型必须使用规范列表；证据必填；复现步骤必须包含 Python 利用脚本。",
		params: map[string]*schema.ParameterInfo{
			"title":              stringParam("兼容短标题；最终标题由系统按固定格式生成"),
			"severity":           stringParam("严重度：critical/high/medium/low/info，默认 medium"),
			"description":        stringParam("漏洞概述：包含漏洞位置、类型、原理和测试链路"),
			"target":             stringParam("受影响目标（URL/IP/端口）"),
			"evidence":           stringParam("证据（请求响应、命令输出摘要）"),
			"evidence_refs":      stringArrayParam("证据引用；" + evidenceReferenceFormatHint),
			"asset_id":           stringParam("关联资产 id（可选，必须是本项目资产）"),
			"intent_id":          stringParam("产生本漏洞的 intent id，用于建立探索链路"),
			"vulnerability_type": stringParam("规范漏洞类型，必须来自平台19类漏洞列表"),
			"parameter":          stringParam("受影响参数名，例如 id、user、file"),
			"http_method":        stringParam("HTTP 方法，例如 GET、POST"),
			"preconditions":      stringParam("环境准备和前置条件"),
			"attack_chain":       stringParam("测试链路；写入漏洞概述"),
			"recommendation":     stringParam("可落地的修复方案"),
			"poc":                stringParam("完整 POC、HTTP 数据包或分阶段复现步骤，末尾必须包含“利用脚本（优先 Python）”及 Python 代码块"),
			"impact":             stringParam("分层危害分析：直接、数据、系统和其他风险"),
			"residual_notes":     stringParam("复测与清理备注；没有复测时写“无”"),
			"reproduction_steps": stringParam("兼容旧调用；poc 为空时作为 POC"),
			"confidence":         integerParam("结论置信度 0-100，默认按严重度计算"),
			"verification_state": stringParam("验证状态：observed/verified/exploitable，默认 verified"),
			"exploitability":     stringParam("可利用性说明"),
			"test_technique":     stringParam("验证技术，例如 boolean/error/union/time-based"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Title             string   `json:"title"`
				Severity          string   `json:"severity"`
				Description       string   `json:"description"`
				Target            string   `json:"target"`
				Evidence          string   `json:"evidence"`
				EvidenceRefs      []string `json:"evidence_refs"`
				AssetID           string   `json:"asset_id"`
				IntentID          string   `json:"intent_id"`
				VulnerabilityType string   `json:"vulnerability_type"`
				Parameter         string   `json:"parameter"`
				HTTPMethod        string   `json:"http_method"`
				Preconditions     string   `json:"preconditions"`
				AttackChain       string   `json:"attack_chain"`
				Recommendation    string   `json:"recommendation"`
				POC               string   `json:"poc"`
				Impact            string   `json:"impact"`
				ResidualNotes     string   `json:"residual_notes"`
				ReproductionSteps string   `json:"reproduction_steps"`
				Confidence        flexInt  `json:"confidence"`
				VerificationState string   `json:"verification_state"`
				Exploitability    string   `json:"exploitability"`
				TestTechnique     string   `json:"test_technique"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			intentID := strings.TrimSpace(request.IntentID)
			var intentNode *database.GraphNode
			if intentID != "" {
				intentNode, err = s.validateGraphNodeKind(ctx, projectID, intentID, "intent")
				if err != nil {
					return "", err
				}
			}
			title := truncateProjectText(request.Title, projectToolShortText)
			severity := strings.ToLower(strings.TrimSpace(request.Severity))
			if severity == "" {
				severity = "medium"
			}
			if !findingSeverities[severity] {
				return "", fmt.Errorf("severity 必须是 critical/high/medium/low/info")
			}
			target := truncateProjectText(request.Target, projectToolShortText*2)
			if target == "" {
				return "", fmt.Errorf("target 不能为空")
			}
			vulnerabilityType, validType := vulnerabilityfmt.NormalizeType(request.VulnerabilityType)
			if !validType {
				return "", fmt.Errorf("vulnerability_type 必须从平台规定列表中选择")
			}
			if title == "" {
				title = vulnerabilityType
			}
			hasEvidence := strings.TrimSpace(request.Evidence) != ""
			for _, ref := range request.EvidenceRefs {
				if strings.TrimSpace(ref) != "" {
					hasEvidence = true
					break
				}
			}
			if !hasEvidence {
				return "", fmt.Errorf("漏洞必须提供 evidence 或 evidence_refs")
			}
			poc := strings.TrimSpace(request.POC)
			if poc == "" {
				poc = strings.TrimSpace(request.ReproductionSteps)
			}
			if (severity == "critical" || severity == "high") && poc == "" {
				return "", fmt.Errorf("%s 漏洞必须提供 POC 或复现步骤", severity)
			}
			if err := vulnerabilityfmt.ValidateReproduction(poc); err != nil {
				return "", err
			}
			impact := strings.TrimSpace(request.Impact)
			if impact == "" {
				return "", fmt.Errorf("impact 不能为空")
			}
			description := strings.TrimSpace(request.Description)
			if chain := strings.TrimSpace(request.AttackChain); chain != "" {
				if description != "" {
					description += "\n"
				}
				description += "测试链路：" + chain
			}
			if err := s.validateEvidenceReferences(
				ctx,
				projectID,
				userID,
				request.EvidenceRefs,
				severity,
			); err != nil {
				return "", err
			}
			confidence := int(request.Confidence)
			if confidence <= 0 {
				confidence = severityEvidenceConfidence(severity)
			}
			verificationState := strings.ToLower(strings.TrimSpace(request.VerificationState))
			if verificationState == "" {
				verificationState = "verified"
			}

			now := time.Now().UTC()
			finding := database.Vulnerability{
				ID:                randomID(),
				ProjectID:         projectID,
				AssetID:           firstNonEmpty(request.AssetID, currentAssetID(ctx)),
				OwnerUserID:       userID,
				Title:             title,
				Severity:          severity,
				Status:            "open",
				VulnerabilityType: vulnerabilityType,
				Target:            target,
				Parameter:         truncateProjectText(request.Parameter, projectToolShortText),
				HTTPMethod:        strings.ToUpper(truncateProjectText(request.HTTPMethod, projectToolShortText)),
				Preconditions:     vulnerabilityfmt.NormalizePreconditions(truncateProjectText(request.Preconditions, projectToolLongText)),
				ReproductionSteps: truncateProjectText(poc, projectToolLongText),
				Description:       truncateProjectText(description, projectToolLongText),
				Evidence:          truncateProjectText(request.Evidence, projectToolLongText),
				EvidenceRefs:      request.EvidenceRefs,
				Impact:            truncateProjectText(impact, projectToolLongText),
				Recommendation:    truncateProjectText(request.Recommendation, projectToolLongText),
				RetestNotes:       vulnerabilityfmt.NormalizeRetestNotes(truncateProjectText(request.ResidualNotes, projectToolLongText)),
				VerificationState: verificationState,
				Confidence:        confidence,
				Exploitability:    truncateProjectText(request.Exploitability, projectToolLongText),
				TestTechnique:     truncateProjectText(request.TestTechnique, projectToolShortText),
				CreatedAt:         now,
				UpdatedAt:         now,
			}
			finding = database.NormalizeVulnerabilityEvidence(finding)
			if err := database.ValidateVulnerabilityEvidence(finding); err != nil {
				return "", err
			}
			if err := validateStandardFindingReport(finding); err != nil {
				return "", err
			}
			if err := s.ReviewVulnerability(ctx, finding); err != nil {
				return "", err
			}
			assetID, err := s.resolveFindingAsset(
				ctx,
				projectID,
				userID,
				request.AssetID,
				target,
				severity,
			)
			if err != nil {
				return "", err
			}
			if err := s.validateCampaignAssetScope(ctx, assetID); err != nil {
				return "", err
			}
			if intentNode != nil && !graphAssetScopeCompatible(assetID, intentNode.AssetID) {
				return "", fmt.Errorf("intent_id 与漏洞不属于同一资产")
			}
			finding.AssetID = assetID
			projectName := "未关联系统"
			projectHints := []string{target, finding.Impact, finding.Description}
			if project, err := s.db.GetProject(ctx, projectID, userID); err == nil {
				if name := strings.TrimSpace(project.Name); name != "" {
					projectName = name
				}
				projectHints = append(projectHints, project.Description, project.Goals, project.Scope)
			}
			assetValue := ""
			assetName := ""
			if assetID != "" {
				if asset, err := s.db.GetAsset(ctx, assetID, userID); err == nil {
					assetValue = asset.Value
					assetName = asset.Name
				}
			}
			projectHints = append(projectHints, assetName, assetValue)
			finding.Title = vulnerabilityfmt.BuildTitle(vulnerabilityfmt.TitleParts{
				ProjectName:          vulnerabilityfmt.InferProductName(projectName, projectHints...),
				VulnerabilityAddress: vulnerabilityfmt.VulnerabilityAddress(target, finding.Title, finding.Description),
				VulnerabilityType:    vulnerabilityType,
				ImpactSummary:        vulnerabilityfmt.ShortImpact(vulnerabilityType),
				ID:                   finding.ID,
			})
			finding = database.NormalizeVulnerabilityEvidence(finding)
			savedFinding, merged, err := s.db.CreateOrMergeVulnerability(ctx, finding)
			if err != nil {
				return "", fmt.Errorf("上报漏洞失败: %w", err)
			}
			finding = *savedFinding
			s.markMissionObjectiveCompleteFromFinding(ctx, savedFinding)
			s.enqueueFindingVerification(ctx, savedFinding)
			saved, err := s.materializeFindingNode(ctx, projectID, savedFinding)
			if err != nil {
				return "", fmt.Errorf("创建攻击路径节点失败: %w", err)
			}
			if intentID != "" {
				if err := s.linkGraphEdge(ctx, projectID, intentID, saved.ID, "yields"); err != nil {
					return "", err
				}
			}
			if !missionSuppressesAutomaticFollowUps(ctx) {
				if err := s.spawnFindingFollowUpIntents(ctx, projectID, savedFinding); err != nil {
					return "", fmt.Errorf("派生漏洞后续意图失败: %w", err)
				}
			}
			if merged {
				if err := s.upsertFindingTestResult(ctx, projectID, savedFinding); err != nil {
					return "", err
				}
				if !missionSuppressesAutomaticFollowUps(ctx) {
					s.seedFollowUpHypotheses(ctx, projectID, *savedFinding)
				}
				s.syncProjectGraph(ctx, projectID, userID)
				return fmt.Sprintf(
					"已合并重复漏洞：%s（id %s，置信度 %d，证据引用 %d；攻击路径节点 %s）",
					savedFinding.Title,
					savedFinding.ID,
					savedFinding.Confidence,
					len(savedFinding.EvidenceRefs),
					saved.ID,
				), nil
			}
			if err := s.upsertFindingTestResult(ctx, projectID, &finding); err != nil {
				return "", err
			}
			if !missionSuppressesAutomaticFollowUps(ctx) {
				s.seedFollowUpHypotheses(ctx, projectID, finding)
			}

			s.syncProjectGraph(ctx, projectID, userID)
			return fmt.Sprintf(
				"已上报漏洞：%s（severity %s，status open，evidenceRefs %d，id %s；攻击路径节点 %s）",
				finding.Title,
				finding.Severity,
				len(finding.EvidenceRefs),
				finding.ID,
				saved.ID,
			), nil
		},
	}
}

// enqueueFindingVerification 为已上报漏洞建立独立验证任务；
// 非 Campaign 对话或无法定位资产时静默跳过，不阻塞漏洞写回。
func (s *Service) enqueueFindingVerification(
	ctx context.Context,
	finding *database.Vulnerability,
) {
	if s == nil || s.db == nil || finding == nil || missionSuppressesAutomaticFollowUps(ctx) {
		return
	}
	campaignID, err := s.resolveCampaignID(ctx, "")
	if err != nil || campaignID == "" {
		return
	}
	_, _ = s.db.EnqueueFindingVerification(
		ctx,
		campaignID,
		finding.ID,
		finding.AssetID,
		finding.Severity,
		finding.Title,
	)
	s.refreshCampaignIntelligence(ctx, campaignID)
}

func severityEvidenceConfidence(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 95
	case "high":
		return 90
	case "medium":
		return 80
	case "low":
		return 70
	default:
		return 60
	}
}

func (s *Service) upsertFindingTestResult(
	ctx context.Context,
	projectID string,
	finding *database.Vulnerability,
) error {
	if finding == nil {
		return nil
	}
	dimension := strings.TrimSpace(finding.VulnerabilityType)
	if dimension == "" {
		dimension = "security-test"
	}
	result := strings.TrimSpace(finding.Description)
	if result == "" {
		result = strings.TrimSpace(finding.Impact)
	}
	_, err := s.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID:    projectID,
		AssetID:      finding.AssetID,
		Dimension:    dimension,
		Technique:    strings.TrimSpace(finding.TestTechnique),
		Status:       "confirmed",
		Result:       truncateProjectText(result, projectToolLongText),
		Evidence:     truncateProjectText(finding.Evidence, projectToolLongText),
		EvidenceRefs: append([]string(nil), finding.EvidenceRefs...),
		Confidence:   finding.Confidence,
		FindingID:    finding.ID,
		CreatedAt:    time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("写入漏洞测试结果失败: %w", err)
	}
	return nil
}

func (s *Service) getFindingTool() tool.BaseTool {
	return &jsonTool{
		name: "project_get_finding",
		desc: "按漏洞 ID 获取当前项目中的完整漏洞详情，包括描述、复现步骤、证据、影响和修复建议。",
		params: map[string]*schema.ParameterInfo{
			"finding_id": stringParam("漏洞 ID", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				FindingID string `json:"finding_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			findingID := strings.TrimSpace(request.FindingID)
			if findingID == "" {
				return "", fmt.Errorf("finding_id 不能为空")
			}
			if len([]rune(findingID)) > 128 {
				return "", fmt.Errorf("finding_id 长度不能超过 128 个字符")
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			item, err := s.db.GetVulnerability(ctx, findingID, userID)
			if errors.Is(err, sql.ErrNoRows) {
				return "", fmt.Errorf("漏洞 %s 不存在", findingID)
			}
			if err != nil {
				return "", fmt.Errorf("读取漏洞失败: %w", err)
			}
			if item == nil || item.ProjectID != projectID {
				return "", fmt.Errorf("漏洞 %s 不属于当前项目", findingID)
			}
			if boundAssetID := currentAssetID(ctx); boundAssetID != "" &&
				strings.TrimSpace(item.AssetID) != "" &&
				!strings.EqualFold(strings.TrimSpace(item.AssetID), boundAssetID) {
				execution, _ := missionExecutionFromContext(ctx)
				if !execution.Plan.ProjectScope {
					return "", fmt.Errorf(
						"漏洞 %s 关联资产 %s 不在当前会话资产 %s 范围内",
						findingID,
						item.AssetID,
						boundAssetID,
					)
				}
			}
			if err := s.validateCampaignAssetScope(ctx, item.AssetID); err != nil {
				return "", err
			}
			return formatProjectFindingDetail(*item), nil
		},
	}
}

func (s *Service) listFindingsTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_findings",
		desc: "列出当前项目已上报的漏洞（可按状态/严重度过滤）。",
		params: map[string]*schema.ParameterInfo{
			"status":   stringParam("按状态过滤：open/confirmed/fixed/ignored/false_positive"),
			"severity": stringParam("按严重度过滤：critical/high/medium/low/info"),
			"query":    stringParam("按标题、目标、类型或资产搜索"),
			"limit":    integerParam("返回条数，默认 20，最大 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Status   string  `json:"status"`
				Severity string  `json:"severity"`
				Query    string  `json:"query"`
				Limit    flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			limit := clampProjectLimit(int(request.Limit), 20)
			items, _, err := s.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
				OwnerUserID: userID,
				ProjectID:   projectID,
				AssetID:     currentAssetID(ctx),
				Status:      strings.TrimSpace(request.Status),
				Severity:    strings.TrimSpace(request.Severity),
				Search:      strings.TrimSpace(request.Query),
				Limit:       limit,
			})
			if err != nil {
				return "", fmt.Errorf("读取项目漏洞失败: %w", err)
			}
			if len(items) == 0 {
				return "当前项目没有匹配的漏洞记录。", nil
			}
			var builder strings.Builder
			for _, item := range items {
				builder.WriteString(fmt.Sprintf(
					"- [%s/%s/%s] %s target=%s asset=%s evidenceRefs=%d confidence=%d id=%s\n",
					item.Severity,
					item.Status,
					item.VerificationState,
					item.Title,
					item.Target,
					item.AssetID,
					len(item.EvidenceRefs),
					item.Confidence,
					item.ID,
				))
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func formatProjectFindingDetail(item database.Vulnerability) string {
	var builder strings.Builder
	builder.WriteString("漏洞详情\n")
	writeField := func(label, value string) {
		fmt.Fprintf(&builder, "%s: %s\n", label, orDefaultProjectToolValue(value, "-"))
	}
	writeField("ID", item.ID)
	writeField("标题", item.Title)
	writeField("严重度", item.Severity)
	writeField("状态", item.Status)
	writeField("漏洞类型", item.VulnerabilityType)
	writeField("目标", item.Target)
	writeField("HTTP 方法", item.HTTPMethod)
	writeField("参数", item.Parameter)
	writeField("资产 ID", item.AssetID)
	writeField("验证状态", item.VerificationState)
	fmt.Fprintf(&builder, "置信度: %d\n", item.Confidence)
	writeField("前置条件", item.Preconditions)
	writeField("描述", item.Description)
	writeField("复现步骤", item.ReproductionSteps)
	writeField("证据", item.Evidence)
	writeField("证据引用", strings.Join(item.EvidenceRefs, ", "))
	writeField("影响", item.Impact)
	writeField("修复建议", item.Recommendation)
	writeField("可利用性", item.Exploitability)
	writeField("测试技术", item.TestTechnique)
	writeField("测试残留与复测记录", item.RetestNotes)
	writeField("创建时间", item.CreatedAt.Format(time.RFC3339))
	writeField("更新时间", item.UpdatedAt.Format(time.RFC3339))
	return builder.String()
}

func (s *Service) graphOverviewTool() tool.BaseTool {
	return &jsonTool{
		name: "project_graph_overview",
		desc: "查看当前资产及项目级公共节点的攻击路径总览；未指定 asset_id 时使用当前对话绑定资产。",
		params: map[string]*schema.ParameterInfo{
			"asset_id": stringParam("资产 id；留空时使用当前对话绑定资产"),
			"limit":    integerParam("每种类型最多返回节点数，默认 10，最大 50"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				AssetID string  `json:"asset_id"`
				Limit   flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			assetID := strings.TrimSpace(request.AssetID)
			if assetID == "" {
				assetID = currentAssetID(ctx)
			}
			if assetID != "" {
				assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
				if err != nil {
					return "", err
				}
			}
			nodes, err := s.db.ListProjectGraphNodesByAsset(ctx, projectID, assetID)
			if err != nil {
				return "", fmt.Errorf("读取攻击路径失败: %w", err)
			}
			nodeIDs := make([]string, 0, len(nodes))
			for _, node := range nodes {
				nodeIDs = append(nodeIDs, node.ID)
			}
			edges, err := s.db.ListProjectGraphEdgesForNodes(ctx, projectID, nodeIDs)
			if err != nil {
				return "", fmt.Errorf("读取攻击路径连线失败: %w", err)
			}
			limit := clampProjectLimit(int(request.Limit), 10)
			byKind := make(map[string][]database.GraphNode)
			for _, node := range nodes {
				byKind[node.Kind] = append(byKind[node.Kind], node)
			}
			var builder strings.Builder
			if assetID != "" {
				builder.WriteString(fmt.Sprintf("资产范围：%s\n", assetID))
			} else {
				builder.WriteString("资产范围：项目全量\n")
			}
			for _, kind := range []string{"begin", "goal", "intent", "fact", "finding", "hint"} {
				group := byKind[kind]
				if len(group) == 0 {
					continue
				}
				builder.WriteString(fmt.Sprintf("[%s] %d 个节点\n", kind, len(group)))
				for index, node := range group {
					if index >= limit {
						builder.WriteString(fmt.Sprintf("  ...（还有 %d 个，已省略）\n", len(group)-limit))
						break
					}
					builder.WriteString(fmt.Sprintf(
						"  - %s | %s | status=%s | severity=%s | id=%s\n",
						node.Title,
						node.Kind,
						node.Status,
						node.Severity,
						node.ID,
					))
				}
			}
			if len(edges) > 0 {
				builder.WriteString(fmt.Sprintf("连线 %d 条：\n", len(edges)))
				for index, edge := range edges {
					if index >= limit {
						break
					}
					builder.WriteString(fmt.Sprintf(
						"  - %s -> %s (%s)\n",
						edge.SrcID,
						edge.DstID,
						edge.Rel,
					))
				}
			}
			if builder.Len() == 0 {
				return "当前项目攻击路径还是空的。", nil
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) graphNodeTool() tool.BaseTool {
	return &jsonTool{
		name: "project_graph_node",
		desc: "查看攻击路径上某个节点的完整内容与关联连线。",
		params: map[string]*schema.ParameterInfo{
			"node_id": stringParam("节点 id（可从 project_graph_overview 获取）", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				NodeID string `json:"node_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			nodeID := strings.TrimSpace(request.NodeID)
			if nodeID == "" {
				return "", fmt.Errorf("node_id 不能为空")
			}
			node, err := s.db.GetProjectGraphNode(ctx, nodeID, projectID)
			if err != nil {
				return "", fmt.Errorf("节点不存在或不属于当前项目: %w", err)
			}
			assetID := currentAssetID(ctx)
			if assetID != "" && node.AssetID != "" && node.AssetID != assetID {
				return "", fmt.Errorf("节点不属于当前对话绑定的资产")
			}
			edges, err := s.db.ListProjectGraphEdges(ctx, projectID)
			if err != nil {
				return "", fmt.Errorf("读取连线失败: %w", err)
			}
			var builder strings.Builder
			builder.WriteString(fmt.Sprintf("节点 %s\n", node.ID))
			builder.WriteString(fmt.Sprintf("- 类型: %s\n", node.Kind))
			builder.WriteString(fmt.Sprintf("- 标题: %s\n", node.Title))
			builder.WriteString(fmt.Sprintf("- 状态: %s\n", node.Status))
			builder.WriteString(fmt.Sprintf("- 置信度: %d\n", node.Confidence))
			if node.Severity != "" {
				builder.WriteString(fmt.Sprintf("- 严重度: %s\n", node.Severity))
			}
			if node.AssetID != "" {
				builder.WriteString(fmt.Sprintf("- 关联资产: %s\n", node.AssetID))
			}
			if node.Detail != "" {
				builder.WriteString(fmt.Sprintf("- 详情: %s\n", node.Detail))
			}
			for _, edge := range edges {
				if edge.SrcID == node.ID {
					builder.WriteString(fmt.Sprintf("- 指向 %s (%s)\n", edge.DstID, edge.Rel))
				}
				if edge.DstID == node.ID {
					builder.WriteString(fmt.Sprintf("- 来自 %s (%s)\n", edge.SrcID, edge.Rel))
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) syncGraphTool() tool.BaseTool {
	return &jsonTool{
		name:   "project_sync_graph",
		desc:   "补全当前项目攻击路径：生成起点/目标骨架，并把已记录的事实与漏洞回填成节点与连线（幂等，可重复调用）。",
		params: map[string]*schema.ParameterInfo{},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct{}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			derived, err := s.ensureBlockedIntentAlternatives(ctx, projectID)
			if err != nil {
				return "", fmt.Errorf("补全 blocked 意图替代路径失败: %w", err)
			}
			project, err := s.db.GetProject(ctx, projectID, userID)
			if err != nil {
				return "", fmt.Errorf("读取项目失败: %w", err)
			}
			result, err := s.db.SyncProjectGraph(ctx, *project)
			if err != nil {
				return "", fmt.Errorf("补全攻击路径失败: %w", err)
			}
			message := fmt.Sprintf(
				"攻击路径已补全：新增节点 %d 个、更新节点 %d 个、新增连线 %d 条。",
				result.CreatedNodes,
				result.UpdatedNodes,
				result.CreatedEdges,
			)
			if derived > 0 {
				message += fmt.Sprintf("已为 blocked 意图派生 %d 条替代路径。", derived)
			}
			return message, nil
		},
	}
}

func (s *Service) addIntentTool() tool.BaseTool {
	return &jsonTool{
		name: "project_add_intent",
		desc: "把一个待验证的攻击意图写入攻击路径；必须携带来源目标、父意图、事实或漏洞，形成可追溯的探索链路。",
		params: map[string]*schema.ParameterInfo{
			"title":             stringParam("意图标题", true),
			"detail":            stringParam("意图说明/验证思路"),
			"status":            stringParam("状态：open/running/done/blocked/exhausted/capacity_blocked，默认 open"),
			"asset_id":          stringParam("关联资产 id（可选，必须是本项目资产）"),
			"parent_intent_id":  stringParam("父意图 id，建立 derived_from 关系"),
			"goal_id":           stringParam("所属目标 id，建立 spawns 关系"),
			"source_fact_id":    stringParam("来源事实 id，建立 derived_from 关系"),
			"source_finding_id": stringParam("来源漏洞 id，建立 derived_from 关系"),
			"success_criteria":  stringParam("成功标准/完成条件"),
			"priority":          integerParam("优先级 0-100，仅用于说明"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Title           string  `json:"title"`
				Detail          string  `json:"detail"`
				Status          string  `json:"status"`
				AssetID         string  `json:"asset_id"`
				ParentIntentID  string  `json:"parent_intent_id"`
				GoalID          string  `json:"goal_id"`
				SourceFactID    string  `json:"source_fact_id"`
				SourceFindingID string  `json:"source_finding_id"`
				SuccessCriteria string  `json:"success_criteria"`
				Priority        flexInt `json:"priority"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			title := normalizeGraphNodeTitle(request.Title)
			if title == "" {
				return "", fmt.Errorf("title 不能为空")
			}
			status := strings.ToLower(strings.TrimSpace(request.Status))
			if status == "" {
				status = "open"
			}
			if !graphNodeStatuses["intent"][status] {
				return "", fmt.Errorf("intent 状态必须是 open/running/done/blocked/exhausted/capacity_blocked")
			}
			assetID := strings.TrimSpace(request.AssetID)
			if assetID == "" {
				assetID = currentAssetID(ctx)
			}
			assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
			if err != nil {
				return "", err
			}
			if err := s.validateCampaignAssetScope(ctx, assetID); err != nil {
				return "", err
			}
			parentIntentID := strings.TrimSpace(request.ParentIntentID)
			if parentID := strings.TrimSpace(request.ParentIntentID); parentID != "" {
				parentNode, err := s.validateGraphNodeKind(ctx, projectID, parentID, "intent")
				if err != nil {
					return "", err
				}
				if !graphAssetScopeCompatible(assetID, parentNode.AssetID) {
					return "", fmt.Errorf("parent_intent_id 与目标 intent 不属于同一资产")
				}
			}
			goalID := strings.TrimSpace(request.GoalID)
			if goalID := strings.TrimSpace(request.GoalID); goalID != "" {
				goalNode, err := s.validateGraphNodeKind(ctx, projectID, goalID, "goal")
				if err != nil {
					return "", err
				}
				if !graphAssetScopeCompatible(assetID, goalNode.AssetID) {
					return "", fmt.Errorf("goal_id 与目标 intent 不属于同一资产")
				}
			}
			sourceFactNodeID := ""
			if factID := strings.TrimSpace(request.SourceFactID); factID != "" {
				fact, err := s.loadActiveFactSource(ctx, projectID, assetID, factID)
				if err != nil {
					return "", err
				}
				factNode, err := s.materializeIntentFactNode(ctx, projectID, fact)
				if err != nil {
					return "", fmt.Errorf("创建来源事实节点失败: %w", err)
				}
				sourceFactNodeID = factNode.ID
			}
			sourceFindingNodeID := ""
			if findingID := strings.TrimSpace(request.SourceFindingID); findingID != "" {
				finding, err := s.loadActiveFindingSource(
					ctx,
					projectID,
					userID,
					assetID,
					findingID,
				)
				if err != nil {
					return "", err
				}
				findingNode, err := s.materializeFindingNode(ctx, projectID, finding)
				if err != nil {
					return "", fmt.Errorf("创建来源漏洞节点失败: %w", err)
				}
				sourceFindingNodeID = findingNode.ID
			}
			// 未显式提供来源时，自动挂到当前资产最近的目标节点，避免产生孤立 intent。
			if parentIntentID == "" &&
				goalID == "" &&
				sourceFactNodeID == "" &&
				sourceFindingNodeID == "" {
				goalID = s.latestIntentSourceRootID(ctx, projectID, assetID)
				if goalID == "" {
					return "", fmt.Errorf("当前项目没有可用目标或起点，请先调用 project_sync_graph 补全攻击路径")
				}
			}
			s.graphWriteMu.Lock()
			defer s.graphWriteMu.Unlock()
			if _, limitMessage, limitErr := s.activeGraphNodeCapacity(
				ctx,
				projectID,
				"intent",
				assetID,
			); limitErr != nil {
				return "", limitErr
			} else if limitMessage != "" {
				return limitMessage, nil
			}
			detail := truncateProjectText(request.Detail, projectToolLongText)
			if criteria := strings.TrimSpace(request.SuccessCriteria); criteria != "" {
				detail = strings.TrimSpace(detail + "\n\n成功标准：" + truncateProjectText(criteria, projectToolLongText))
			}
			if request.Priority > 0 {
				detail = strings.TrimSpace(fmt.Sprintf("%s\n\n优先级：%d", detail, request.Priority))
			}
			now := time.Now().UTC()
			saved, err := s.db.UpsertProjectGraphNode(ctx, database.GraphNode{
				ID:         randomID(),
				ProjectID:  projectID,
				Kind:       "intent",
				Title:      title,
				Detail:     detail,
				Status:     status,
				Confidence: 70,
				AssetID:    assetID,
				Source:     "agent",
				CreatedAt:  now,
				UpdatedAt:  now,
			})
			if err != nil {
				return "", fmt.Errorf("写入攻击路径 intent 失败: %w", err)
			}
			links := 0
			for _, item := range []struct {
				sourceID string
				rel      string
			}{
				{parentIntentID, "derived_from"},
				{sourceFactNodeID, "derived_from"},
				{sourceFindingNodeID, "derived_from"},
				{goalID, "spawns"},
			} {
				if item.sourceID == "" {
					continue
				}
				if err := s.linkGraphEdge(ctx, projectID, item.sourceID, saved.ID, item.rel); err != nil {
					return "", err
				}
				links++
			}
			s.syncProjectGraph(ctx, projectID, userID)
			return fmt.Sprintf(
				"已写入 intent：%s（status %s，id %s，来源边 %d）",
				saved.Title,
				saved.Status,
				saved.ID,
				links,
			), nil
		},
	}
}

func (s *Service) addHintTool() tool.BaseTool {
	return &jsonTool{
		name: "project_add_hint",
		desc: "把一个战术提示写入当前项目攻击路径（hint 节点），供后续规划参考。",
		params: map[string]*schema.ParameterInfo{
			"title":    stringParam("提示标题", true),
			"detail":   stringParam("提示内容"),
			"asset_id": stringParam("关联资产 id（可选，必须是本项目资产）"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			return s.addGraphNode(ctx, raw, "hint", "active")
		},
	}
}

// addGraphNode 是 intent/hint 两个写工具的共用实现。
func (s *Service) addGraphNode(
	ctx context.Context,
	raw string,
	kind string,
	defaultStatus string,
) (string, error) {
	var request struct {
		Title   string `json:"title"`
		Detail  string `json:"detail"`
		Status  string `json:"status"`
		AssetID string `json:"asset_id"`
	}
	if err := decodeToolArgs(raw, &request); err != nil {
		return "", err
	}
	_, userID, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", err
	}
	title := truncateProjectText(request.Title, projectToolShortText)
	if title == "" {
		return "", fmt.Errorf("title 不能为空")
	}
	status := strings.ToLower(strings.TrimSpace(request.Status))
	if status == "" {
		status = defaultStatus
	}
	if allowed := graphNodeStatuses[kind]; allowed != nil && !allowed[status] {
		keys := make([]string, 0, len(allowed))
		for key := range allowed {
			keys = append(keys, key)
		}
		return "", fmt.Errorf("%s 的状态必须是 %s", kind, strings.Join(keys, "/"))
	}
	assetID := strings.TrimSpace(request.AssetID)
	if assetID == "" {
		assetID = currentAssetID(ctx)
	}
	assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
	if err != nil {
		return "", err
	}
	if err := s.validateCampaignAssetScope(ctx, assetID); err != nil {
		return "", err
	}
	title = normalizeGraphNodeTitle(title)
	if title == "" {
		return "", fmt.Errorf("title 规范化后为空")
	}
	s.graphWriteMu.Lock()
	defer s.graphWriteMu.Unlock()
	if _, limitMessage, limitErr := s.activeGraphNodeCapacity(
		ctx,
		projectID,
		kind,
		assetID,
	); limitErr != nil {
		return "", limitErr
	} else if limitMessage != "" {
		return limitMessage, nil
	}
	now := time.Now().UTC()
	node := database.GraphNode{
		ID:         randomID(),
		ProjectID:  projectID,
		Kind:       kind,
		Title:      title,
		Detail:     truncateProjectText(request.Detail, projectToolLongText),
		Status:     status,
		Confidence: 70,
		AssetID:    assetID,
		Source:     "agent",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	saved, err := s.db.UpsertProjectGraphNode(ctx, node)
	if err != nil {
		return "", fmt.Errorf("写入攻击路径节点失败: %w", err)
	}
	s.syncProjectGraph(ctx, projectID, userID)
	return fmt.Sprintf(
		"已写入攻击路径 %s 节点：%s（status %s，id %s）",
		kind,
		saved.Title,
		saved.Status,
		saved.ID,
	), nil
}

func (s *Service) resolveCampaignID(
	ctx context.Context,
	requested string,
) (string, error) {
	campaignID, _, _, err := s.currentCampaign(ctx, requested)
	return campaignID, err
}

func (s *Service) currentCampaign(
	ctx context.Context,
	requested string,
) (string, string, string, error) {
	conversation, userID, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", "", "", err
	}
	campaignID := strings.TrimSpace(requested)
	if campaignID == "" {
		campaignID = strings.TrimSpace(execctx.CampaignID(ctx))
	}
	if campaignID == "" {
		campaignID = strings.TrimSpace(conversation.BatchID)
	}
	if campaignID == "" {
		if task, taskErr := s.db.GetCampaignTaskByConversation(
			ctx,
			conversation.ID,
			userID,
		); taskErr == nil && task != nil {
			campaignID = task.CampaignID
		}
	}
	if campaignID != "" {
		campaign, err := s.db.GetCampaign(ctx, campaignID, userID)
		if err != nil {
			return "", "", "", fmt.Errorf("批量任务不存在或无权访问")
		}
		if campaign.ProjectID != projectID {
			return "", "", "", fmt.Errorf("批量任务不属于当前项目")
		}
	}
	return campaignID, userID, projectID, nil
}

// currentProject 从 execctx 解析当前会话绑定的项目。
func (s *Service) currentProject(ctx context.Context) (*database.Conversation, string, string, error) {
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return nil, "", "", fmt.Errorf("缺少会话上下文，无法定位当前项目")
	}
	if s.db == nil {
		return nil, "", "", fmt.Errorf("数据库不可用")
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		return nil, "", "", fmt.Errorf("读取当前会话失败: %w", err)
	}
	projectID := strings.TrimSpace(conversation.ProjectID)
	if projectID == "" {
		return nil, "", "", fmt.Errorf("当前对话未绑定项目，无法使用项目工具")
	}
	if _, err := s.db.GetActiveProject(ctx, projectID, userID); err != nil {
		return nil, "", "", err
	}
	return conversation, userID, projectID, nil
}

// syncProjectGraph 合并短时间内的重复同步请求，后台刷新攻击路径与记忆图。
func (s *Service) syncProjectGraph(ctx context.Context, projectID, userID string) {
	_ = ctx
	if s == nil || s.db == nil {
		return
	}
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	if projectID == "" || userID == "" {
		return
	}
	key := projectID + "\x00" + userID

	s.syncMu.Lock()
	if s.projectSyncs == nil {
		s.projectSyncs = map[string]*projectSyncState{}
	}
	state := s.projectSyncs[key]
	if state == nil {
		state = &projectSyncState{}
		s.projectSyncs[key] = state
	}
	state.dirty = true
	if !state.running && !state.scheduled {
		state.scheduled = true
		time.AfterFunc(projectSyncDebounce, func() {
			s.runProjectSync(key, projectID, userID)
		})
	}
	s.syncMu.Unlock()
}

func (s *Service) runProjectSync(key string, projectID string, userID string) {
	s.syncMu.Lock()
	state := s.projectSyncs[key]
	if state == nil || state.running {
		s.syncMu.Unlock()
		return
	}
	state.scheduled = false
	state.running = true
	state.dirty = false
	s.syncMu.Unlock()

	for {
		s.syncProjectGraphNow(projectID, userID)

		s.syncMu.Lock()
		if state.dirty {
			state.dirty = false
			s.syncMu.Unlock()
			continue
		}
		state.running = false
		s.syncMu.Unlock()
		return
	}
}

func (s *Service) syncProjectGraphNow(projectID string, userID string) {
	ctx, cancel := context.WithTimeout(context.Background(), projectSyncTimeout)
	defer cancel()
	project, err := s.db.GetProject(ctx, projectID, userID)
	if err != nil {
		return
	}
	_, _ = s.ensureBlockedIntentAlternatives(ctx, projectID)
	_, _ = s.db.SyncProjectGraph(ctx, *project)
	_ = s.db.SyncProjectMemory(ctx, projectID, userID)
}

func (s *Service) resolveFindingAsset(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
	target string,
	severity string,
) (string, error) {
	if scopeAssetID := currentAssetID(ctx); scopeAssetID != "" {
		assetID = strings.TrimSpace(assetID)
		if assetID != "" && assetID != scopeAssetID {
			return "", fmt.Errorf("漏洞关联资产不属于当前对话绑定的资产")
		}
		assetID = scopeAssetID
	}
	if resolved, err := s.validateProjectAsset(ctx, projectID, userID, assetID); err != nil {
		return "", err
	} else if resolved != "" {
		return resolved, nil
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil
	}
	items, err := s.db.ListProjectAssets(ctx, projectID, userID)
	if err != nil {
		return "", fmt.Errorf("读取项目资产失败: %w", err)
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Value), target) {
			return item.ID, nil
		}
	}

	now := time.Now().UTC()
	kind := inferFindingAssetKind(target)
	if kind == "" {
		return "", nil
	}
	item := database.Asset{
		ID:          randomID(),
		ProjectID:   projectID,
		OwnerUserID: userID,
		Name:        truncateProjectText(target, projectToolShortText),
		Kind:        kind,
		Value:       target,
		Status:      "active",
		Criticality: "medium",
		RiskScore:   severityRiskScore(severity),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.db.CreateAsset(ctx, item); err != nil {
		return "", fmt.Errorf("自动登记关联资产失败: %w", err)
	}
	return item.ID, nil
}

func inferFindingAssetKind(value string) string {
	value = strings.TrimSpace(value)
	if _, err := database.NormalizeAssetValue("url", value); err == nil {
		return "url"
	}
	if _, err := database.NormalizeAssetValue("ip", value); err == nil {
		return "ip"
	}
	if _, err := database.NormalizeAssetValue("domain", value); err == nil {
		return "domain"
	}
	if _, err := database.NormalizeAssetValue("port", value); err == nil {
		return "port"
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return "host"
	}
	if host, err := database.NormalizeAssetValue("host", value); err == nil && !strings.Contains(host, ".") {
		return "host"
	}
	return ""
}

func severityRiskScore(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 100
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 20
	default:
		return 0
	}
}

// validateProjectAsset 校验资产归属；空 id 返回空串。
func (s *Service) validateProjectAsset(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
) (string, error) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return "", nil
	}
	items, err := s.db.ListProjectAssets(ctx, projectID, userID)
	if err != nil {
		return "", fmt.Errorf("读取项目资产失败: %w", err)
	}
	for _, item := range items {
		if item.ID == assetID {
			return assetID, nil
		}
	}
	return "", fmt.Errorf("资产 %s 不属于当前项目", assetID)
}

func decodeToolArgs(raw string, target interface{}) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		trimmed = "{}"
	}
	if err := json.Unmarshal([]byte(trimmed), target); err != nil {
		return fmt.Errorf("解析工具参数失败: %w", err)
	}
	return nil
}

func clampProjectLimit(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value > projectToolListLimit {
		return projectToolListLimit
	}
	return value
}

func projectTextMatches(query string, values ...string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			return true
		}
	}
	return false
}

func truncateProjectText(value string, max int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= max {
		return string(runes)
	}
	return string(runes[:max]) + "…"
}

func capProjectOutput(builder *strings.Builder) string {
	return truncateProjectText(builder.String(), projectToolOutputLimit)
}

func assetKey(kind, value string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + strings.ToLower(strings.TrimSpace(value))
}
