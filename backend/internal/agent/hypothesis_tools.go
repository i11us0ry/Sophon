package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	maxHypothesesPerPlan   = 4
	maxFollowUpPerFinding  = 5
	assetAccessBlockLimit  = 2
	assetAccessBlockWindow = 10 * time.Minute
	accessBlockReasonTag   = "[access_block:"
)

type hypothesisInput struct {
	AssetID          string   `json:"asset_id"`
	ParentIDs        []string `json:"parent_ids"`
	Dimension        string   `json:"dimension"`
	Technique        string   `json:"technique"`
	Rationale        string   `json:"rationale"`
	ExpectedEvidence string   `json:"expected_evidence"`
	Priority         int      `json:"priority"`
	Required         *bool    `json:"required"`
}

var highRiskUploadEntryAliases = []struct {
	name    string
	markers []string
}{
	{name: "ScpSupRegHandler", markers: []string{"scpsupreghandler", "supregattach"}},
	{name: "FileUpload.ashx", markers: []string{"fileupload.ashx", "fileupload.processrequest"}},
	{name: "MOBFileUpload", markers: []string{"mobfileupload"}},
	{name: "KDFileProxyHandler", markers: []string{"kdfileproxyhandler", "*.kdfile"}},
	{name: "UEditor up.ashx", markers: []string{"ueditor", "up.ashx"}},
	{name: "MobileUpload", markers: []string{"mobileupload"}},
	{name: "SaveHttpRequestFile", markers: []string{"savehttprequestfile"}},
}

var uploadEvidenceLocatorPattern = regexp.MustCompile(
	`(?i)(?:IL_[0-9A-F]{4}|rva\s*=\s*0x[0-9A-F]+|\.(?:cs|ashx|aspx|config)\s*:\s*\d+|line\s+\d+)`,
)

func (s *Service) planHypothesesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_plan_hypotheses",
		desc: "批量规划结构化安全测试假设。每个假设包含资产、测试维度、技术、依据、预期证据和优先级。",
		params: map[string]*schema.ParameterInfo{
			"hypotheses_json": stringParam(
				`JSON 数组，单次最多 4 个，例如 [{"asset_id":"asset-1","parent_ids":["fact-node-1"],"dimension":"SQL注入","technique":"time-based","rationale":"数据库参数未参数化","expected_evidence":"可重复延时响应","priority":80}]；源码或附件级审计可省略 asset_id`,
				true,
			),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesesJSON string `json:"hypotheses_json"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			var inputs []hypothesisInput
			if err := json.Unmarshal([]byte(strings.TrimSpace(request.HypothesesJSON)), &inputs); err != nil {
				return "", fmt.Errorf("hypotheses_json 解析失败: %w", err)
			}
			if len(inputs) == 0 || len(inputs) > maxHypothesesPerPlan {
				return "", fmt.Errorf("单次必须规划 1-%d 个假设", maxHypothesesPerPlan)
			}
			maxHypotheses := s.configSnapshot().AgentMaxHypotheses
			total, err := s.db.CountProjectHypotheses(ctx, projectID)
			if err != nil {
				return "", fmt.Errorf("读取假设数量失败: %w", err)
			}
			if maxHypotheses > 0 {
				if total >= maxHypotheses {
					return fmt.Sprintf(
						"活跃假设已达到上限 %d。不要再新增假设；请直接执行并用 project_record_fact 写回事实，"+
							"用 project_record_test 写回 tested_clean/blocked/suspicious/confirmed 测试结果。",
						maxHypotheses,
					), nil
				}
				if remaining := maxHypotheses - total; remaining < len(inputs) {
					inputs = inputs[:remaining]
				}
			}
			skipped := 0
			planned := 0
			assetlessSourceAudit, err := s.allowAssetlessSourceAudit(ctx, projectID, userID)
			if err != nil {
				return "", err
			}
			activeHypotheses, err := s.db.ListActiveProjectHypotheses(ctx, projectID)
			if err != nil {
				return "", fmt.Errorf("读取现有假设失败: %w", err)
			}
			plannedDimensions := make([]hypothesisDimensionRef, 0, len(activeHypotheses))
			for _, item := range activeHypotheses {
				switch item.ExecutionState {
				case database.ProjectExecutionOpen,
					database.ProjectExecutionRunning,
					database.ProjectExecutionPaused:
					plannedDimensions = append(plannedDimensions, hypothesisDimensionRef{
						AssetID:   item.AssetID,
						Dimension: item.Dimension,
					})
				}
			}
			for _, input := range inputs {
				scopeAssetID := currentAssetID(ctx)
				if scopeAssetID != "" &&
					strings.TrimSpace(input.AssetID) != "" &&
					!strings.EqualFold(strings.TrimSpace(input.AssetID), scopeAssetID) {
					return "", fmt.Errorf("当前资产焦点只允许规划资产 %s 的假设", scopeAssetID)
				}
				assetID := firstNonEmpty(input.AssetID, currentAssetID(ctx))
				if assetID != "" {
					assetID, err = s.validateProjectAsset(ctx, projectID, userID, assetID)
					if err != nil {
						return "", err
					}
					blocked, blockedErr := s.db.ProjectAssetWorkBlocked(ctx, projectID, assetID)
					if blockedErr != nil {
						return "", fmt.Errorf("读取资产阻断状态失败: %w", blockedErr)
					}
					if blocked {
						skipped++
						continue
					}
				} else if !assetlessSourceAudit {
					return "", fmt.Errorf("asset_id 不能为空；只有项目无网络资产且存在上传附件时才能创建源码审计假设")
				}
				parentNodes, err := s.resolveHypothesisParents(
					ctx,
					projectID,
					assetID,
					input.ParentIDs,
				)
				if err != nil {
					return "", err
				}
				dimension := truncateProjectText(input.Dimension, projectToolShortText)
				technique := truncateProjectText(input.Technique, projectToolShortText)
				if dimension == "" {
					skipped++
					continue
				}
				if overlappingHypothesisIndex(plannedDimensions, assetID, dimension) >= 0 {
					skipped++
					continue
				}
				entries := highRiskUploadEntries(dimension + "\n" + technique + "\n" + input.Rationale)
				if len(entries) > 1 {
					return "", fmt.Errorf(
						"上传假设包含多个高风险入口（%s）。必须为每个入口单独建立假设，分别验证鉴权、文件名、路径、扩展名和落盘影响",
						strings.Join(entries, "、"),
					)
				}
				priority := input.Priority
				if priority <= 0 {
					priority = 60
				}
				if priority > 100 {
					priority = 100
				}
				required := true
				if input.Required != nil {
					required = *input.Required
				}
				if existing, existingErr := s.db.GetProjectTestResult(
					ctx,
					projectID,
					assetID,
					dimension,
					technique,
				); existingErr == nil && existing != nil {
					skipped++
					continue
				} else if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
					return "", fmt.Errorf("检查已有测试意图失败: %w", existingErr)
				}
				now := time.Now().UTC()
				intentTitle := strings.TrimSpace(dimension)
				if technique != "" {
					intentTitle += " · " + technique
				}
				intentNode := database.GraphNode{
					ID:         randomID(),
					ProjectID:  projectID,
					Kind:       "intent",
					Title:      truncateProjectText(intentTitle, projectToolShortText),
					Detail:     truncateProjectText(input.Rationale, projectToolLongText),
					Status:     "open",
					Confidence: 70,
					AssetID:    assetID,
					Source:     "planner",
					CreatedAt:  now,
					UpdatedAt:  now,
				}
				edges := make([]database.GraphEdge, 0, len(parentNodes)+1)
				if rootID := s.latestIntentSourceRootID(ctx, projectID, assetID); rootID != "" {
					edges = append(edges, database.GraphEdge{
						ID:        randomID(),
						ProjectID: projectID,
						SrcID:     rootID,
						DstID:     intentNode.ID,
						Rel:       "spawns",
						CreatedAt: now,
					})
				}
				for _, parent := range parentNodes {
					edges = append(edges, database.GraphEdge{
						ID:        randomID(),
						ProjectID: projectID,
						SrcID:     parent.ID,
						DstID:     intentNode.ID,
						Rel:       "derived_from",
						CreatedAt: now,
					})
				}
				_, err = s.db.CreateProjectIntentWithHypothesis(ctx, intentNode, edges, database.ProjectTestResult{
					ProjectID:            projectID,
					AssetID:              assetID,
					Dimension:            dimension,
					Technique:            technique,
					Status:               "untested",
					IntentID:             intentNode.ID,
					OriginConversationID: execctx.ConversationID(ctx),
					OriginRunID:          execctx.RunID(ctx),
					Rationale:            truncateProjectText(input.Rationale, projectToolLongText),
					Expected:             truncateProjectText(input.ExpectedEvidence, projectToolLongText),
					Priority:             priority,
					Required:             required,
					CreatedAt:            now,
				})
				if err != nil {
					return "", fmt.Errorf("写入测试假设失败: %w", err)
				}
				plannedDimensions = append(plannedDimensions, hypothesisDimensionRef{
					AssetID:   assetID,
					Dimension: dimension,
				})
				planned++
			}
			if planned > 0 {
				s.syncProjectGraph(ctx, projectID, userID)
			}
			message := fmt.Sprintf("测试假设已规划：写入 %d 个，跳过 %d 个。", planned, skipped)
			if maxHypotheses > 0 && total+planned >= maxHypotheses {
				message += fmt.Sprintf(
					" 活跃假设已达到上限 %d；后续不要继续新增假设，直接使用 project_record_fact 和 project_record_test 写回事实与测试结果。",
					maxHypotheses,
				)
			}
			if handle := s.orchestrationFor(execctx.ConversationID(ctx)); handle != nil {
				handle.signalWorkers()
			}
			return message, nil
		},
	}
}

func (s *Service) resolveHypothesisParents(
	ctx context.Context,
	projectID string,
	assetID string,
	parentIDs []string,
) ([]database.GraphNode, error) {
	parents := make([]database.GraphNode, 0, len(parentIDs))
	for _, parentID := range normalizeUniqueStrings(parentIDs) {
		parent, err := s.db.GetProjectGraphNode(ctx, parentID, projectID)
		if err != nil || parent == nil {
			return nil, fmt.Errorf("父节点 %s 不存在或不属于当前项目", parentID)
		}
		switch strings.ToLower(strings.TrimSpace(parent.Kind)) {
		case "fact", "finding", "intent":
		default:
			return nil, fmt.Errorf("父节点 %s 必须是 fact、finding 或 intent", parentID)
		}
		if !graphAssetScopeCompatible(assetID, parent.AssetID) {
			return nil, fmt.Errorf("父节点 %s 与假设目标不属于同一资产范围", parentID)
		}
		parents = append(parents, *parent)
	}
	return parents, nil
}

type hypothesisDimensionRef struct {
	AssetID   string
	Dimension string
}

func overlappingHypothesisIndex(
	items []hypothesisDimensionRef,
	assetID string,
	dimension string,
) int {
	assetID = strings.TrimSpace(assetID)
	for index, item := range items {
		if strings.TrimSpace(item.AssetID) != assetID {
			continue
		}
		if hypothesisDimensionsOverlap(item.Dimension, dimension) {
			return index
		}
	}
	return -1
}

func hypothesisDimensionsOverlap(left, right string) bool {
	left = canonicalHypothesisDimension(left)
	right = canonicalHypothesisDimension(right)
	if left == "" || right == "" {
		return false
	}
	if left == right {
		return true
	}
	if len([]rune(left)) < 4 || len([]rune(right)) < 4 {
		return false
	}
	return strings.Contains(left, right) || strings.Contains(right, left)
}

func canonicalHypothesisDimension(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(character) || unicode.IsNumber(character) {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func highRiskUploadEntries(value string) []string {
	lower := strings.ToLower(value)
	found := make([]string, 0, 2)
	for _, entry := range highRiskUploadEntryAliases {
		for _, marker := range entry.markers {
			if strings.Contains(lower, marker) {
				found = append(found, entry.name)
				break
			}
		}
	}
	return found
}

func (s *Service) listHypothesesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_hypotheses",
		desc: "查看当前项目的测试意图，包含执行状态、结果状态、暂停/停止/耗尽原因。",
		params: map[string]*schema.ParameterInfo{
			"status": stringParam("可选：untested/running/paused/blocked/stopped/exhausted/suspicious/confirmed"),
			"query":  stringParam("按维度、技术、依据或预期证据搜索"),
			"limit":  integerParam("返回条数，默认 20，最大 100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Status string  `json:"status"`
				Query  string  `json:"query"`
				Limit  flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 100 {
				limit = 20
			}
			query := strings.ToLower(strings.TrimSpace(request.Query))
			fetchLimit := limit
			if query != "" {
				fetchLimit = 100
			}
			items, err := s.db.ListProjectHypotheses(ctx, projectID, request.Status, fetchLimit)
			if err != nil {
				return "", fmt.Errorf("读取测试假设失败: %w", err)
			}
			if len(items) == 0 {
				return "当前项目没有待处理的测试假设。", nil
			}
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if query != "" && !projectTextMatches(query, item.Dimension, item.Technique, item.Rationale, item.Expected, item.AssetID, item.ID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				builder.WriteString(fmt.Sprintf(
					"- [%s/%s] %s/%s（asset=%s，required=%t，priority=%d，attempts=%d，id=%s）\n",
					orDefaultProjectToolValue(item.ExecutionState, item.Status),
					orDefaultProjectToolValue(item.OutcomeState, "unknown"),
					item.Dimension,
					orDefaultProjectToolValue(item.Technique, "-"),
					item.AssetID,
					item.Required,
					item.Priority,
					item.Attempts,
					item.ID,
				))
				if item.Rationale != "" {
					builder.WriteString("  依据: " + truncateProjectText(item.Rationale, projectToolShortText) + "\n")
				}
				if item.Expected != "" {
					builder.WriteString("  预期证据: " + truncateProjectText(item.Expected, projectToolShortText) + "\n")
				}
				if item.StateReason != "" {
					builder.WriteString("  状态原因: " + truncateProjectText(item.StateReason, projectToolShortText) + "\n")
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) startHypothesisTool() tool.BaseTool {
	return &jsonTool{
		name: "project_start_hypothesis",
		desc: "Worker 领取并开始一个测试假设，状态更新为 running 并增加尝试次数。",
		params: map[string]*schema.ParameterInfo{
			"hypothesis_id": stringParam("测试假设 id", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesisID string `json:"hypothesis_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			current, err := s.db.GetProjectTestResultByID(ctx, projectID, request.HypothesisID)
			if err != nil {
				return "", fmt.Errorf("开始测试假设失败: %w", err)
			}
			if err := validateWorkerHypothesisAccess(ctx, current); err != nil {
				return "", err
			}
			item, err := s.db.StartProjectHypothesis(ctx, projectID, request.HypothesisID)
			if err != nil {
				return "", fmt.Errorf("开始测试假设失败: %w", err)
			}
			return fmt.Sprintf(
				"测试假设已开始：%s/%s（attempts=%d，id=%s）",
				item.Dimension,
				orDefaultProjectToolValue(item.Technique, "-"),
				item.Attempts,
				item.ID,
			), nil
		},
	}
}

func (s *Service) completeHypothesisTool() tool.BaseTool {
	return &jsonTool{
		name: "project_complete_hypothesis",
		desc: "完成一个测试意图并写回执行状态、结果状态、结论、证据和关联漏洞。",
		params: map[string]*schema.ParameterInfo{
			"hypothesis_id": stringParam("测试假设 id", true),
			"status":        stringParam("完成状态：tested_clean/blocked/suspicious/confirmed/stopped/exhausted", true),
			"state_reason":  stringParam("执行终态原因，例如 model_error/budget_exhausted/no_evidence/user_stopped"),
			"result":        stringParam("测试结论"),
			"evidence":      stringParam("证据摘要"),
			"evidence_refs": stringArrayParam("证据引用数组；" + evidenceReferenceFormatHint),
			"confidence":    integerParam("置信度 0-100"),
			"finding_id":    stringParam("confirmed 时关联漏洞 id"),
			"block_kind":    stringParam("blocked 时填写 waf/target_unreachable/other；同一资产连续 2 次访问阻断会停止该资产全部意图"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesisID string   `json:"hypothesis_id"`
				Status       string   `json:"status"`
				StateReason  string   `json:"state_reason"`
				BlockKind    string   `json:"block_kind"`
				Result       string   `json:"result"`
				Evidence     string   `json:"evidence"`
				EvidenceRefs []string `json:"evidence_refs"`
				Confidence   flexInt  `json:"confidence"`
				FindingID    string   `json:"finding_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			item, err := s.db.GetProjectTestResultByID(ctx, projectID, request.HypothesisID)
			if err != nil {
				return "", fmt.Errorf("测试假设不存在: %w", err)
			}
			if err := validateWorkerHypothesisAccess(ctx, item); err != nil {
				return "", err
			}
			if item.Status == "stopped" && item.StateReason == database.AssetUserStopReason {
				return "", fmt.Errorf("资产已被用户停止探测，禁止覆盖已停止的测试假设")
			}
			status, ok := database.NormalizeProjectTestResultStatus(request.Status)
			if !ok || !database.IsProjectTestResultTerminal(status) {
				return "", fmt.Errorf("完成状态必须是 tested_clean/blocked/suspicious/confirmed/stopped/exhausted")
			}
			result := truncateProjectText(request.Result, projectToolLongText)
			evidence := truncateProjectText(request.Evidence, projectToolLongText)
			evidenceRefs := append([]string(nil), request.EvidenceRefs...)
			stateReason := strings.TrimSpace(request.StateReason)
			switch status {
			case "tested_clean":
				if result == "" || (evidence == "" && len(evidenceRefs) == 0) {
					return "", fmt.Errorf("tested_clean 必须提供测试结论和证据")
				}
				if isUploadAuditHypothesis(*item) {
					if err := validateUploadCleanEvidence(result, evidence, evidenceRefs); err != nil {
						return "", err
					}
				}
			case "blocked":
				if result == "" {
					return "", fmt.Errorf("blocked 必须说明阻断原因")
				}
			case "suspicious":
				if result == "" {
					return "", fmt.Errorf("suspicious 必须提供测试结论")
				}
			case "confirmed":
				if strings.TrimSpace(request.FindingID) == "" {
					return "", fmt.Errorf("confirmed 必须关联 finding_id")
				}
				if evidence == "" && len(evidenceRefs) == 0 {
					return "", fmt.Errorf("confirmed 必须提供证据")
				}
				if _, err := s.validateProjectFindingID(ctx, projectID, userID, request.FindingID); err != nil {
					return "", err
				}
				if err := s.validateEvidenceReferences(ctx, projectID, userID, evidenceRefs, "high"); err != nil {
					return "", err
				}
			case "stopped", "exhausted":
				if result == "" && stateReason == "" {
					return "", fmt.Errorf("%s 必须说明原因", status)
				}
			}
			if status == "blocked" {
				blockKind := resolveAccessBlockKind(
					request.BlockKind,
					stateReason,
					result,
					evidence,
				)
				stateReason = formatAccessBlockStateReason(blockKind, stateReason, result)
			}
			item.Status = status
			item.StateReason = stateReason
			item.Result = result
			item.Evidence = evidence
			item.EvidenceRefs = evidenceRefs
			item.Confidence = clampInt(int(request.Confidence), 0, 100)
			item.FindingID = strings.TrimSpace(request.FindingID)
			item.UpdatedAt = time.Now().UTC()
			saved, err := s.db.UpsertProjectTestResult(ctx, *item)
			if err != nil {
				return "", fmt.Errorf("完成测试假设失败: %w", err)
			}
			s.syncIntentNodeFromHypothesis(
				ctx,
				projectID,
				saved.IntentID,
				saved.ExecutionState,
				saved.StateReason,
			)
			message := fmt.Sprintf(
				"测试假设已完成：%s/%s，status=%s，confidence=%d（id=%s）",
				saved.Dimension,
				orDefaultProjectToolValue(saved.Technique, "-"),
				saved.Status,
				saved.Confidence,
				saved.ID,
			)
			if saved.Status == "blocked" && saved.AssetID != "" {
				blocked, blockReason, blockErr := s.blockAssetAfterRepeatedAccessFailure(
					ctx,
					projectID,
					userID,
					saved.AssetID,
				)
				if blockErr != nil {
					return "", fmt.Errorf("检查资产级访问阻断失败: %w", blockErr)
				}
				if blocked {
					message += "；" + blockReason
				}
			}
			return message, nil
		},
	}
}

func resolveAccessBlockKind(explicit, stateReason, result, evidence string) string {
	switch kind := strings.ToLower(strings.TrimSpace(explicit)); kind {
	case "waf", "target_unreachable", "other":
		return kind
	}
	text := strings.ToLower(strings.Join([]string{stateReason, result, evidence}, "\n"))
	switch {
	case containsAnyText(text,
		"waf",
		"web application firewall",
		"challenge",
		"cloudflare",
		"云盾",
		"安全狗",
		"雷池",
		"访问被拦截",
		"拦截页",
	):
		return "waf"
	case containsAnyText(text,
		"target_unreachable",
		"unreachable",
		"connection refused",
		"no route to host",
		"no such host",
		"name resolution",
		"dns",
		"timed out",
		"timeout",
		"无法访问",
		"不可达",
		"无法连接",
		"连接被拒绝",
		"拒绝连接",
		"关站",
		"停止服务",
		"超时",
	):
		return "target_unreachable"
	default:
		return "other"
	}
}

func formatAccessBlockStateReason(kind, stateReason, result string) string {
	if kind == "" || kind == "other" {
		return strings.TrimSpace(stateReason)
	}
	reason := strings.TrimSpace(stateReason)
	if reason == "" {
		reason = strings.TrimSpace(result)
	}
	if reason == "" {
		reason = "目标访问受阻"
	}
	return accessBlockReasonTag + kind + "] " + reason
}

func accessBlockKindFromStateReason(stateReason string) string {
	value := strings.ToLower(strings.TrimSpace(stateReason))
	switch {
	case strings.HasPrefix(value, accessBlockReasonTag+"waf]"):
		return "waf"
	case strings.HasPrefix(value, accessBlockReasonTag+"target_unreachable]"):
		return "target_unreachable"
	default:
		return ""
	}
}

func accessBlockKindLabel(kind string) string {
	switch kind {
	case "waf":
		return "WAF 拦截"
	case "target_unreachable":
		return "目标不可达"
	default:
		return "访问受阻"
	}
}

func (s *Service) blockAssetAfterRepeatedAccessFailure(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
) (bool, string, error) {
	items, err := s.db.RecentTerminalProjectTestResultsByAsset(
		ctx,
		projectID,
		assetID,
		time.Now().UTC().Add(-assetAccessBlockWindow),
		assetAccessBlockLimit,
	)
	if err != nil {
		return false, "", err
	}
	if len(items) < assetAccessBlockLimit {
		return false, "", nil
	}
	if strings.TrimSpace(items[0].IntentID) == "" ||
		strings.TrimSpace(items[0].IntentID) == strings.TrimSpace(items[1].IntentID) {
		return false, "", nil
	}
	firstKind := ""
	secondKind := ""
	for index := 0; index < assetAccessBlockLimit; index++ {
		if items[index].Status != "blocked" {
			return false, "", nil
		}
		kind := accessBlockKindFromStateReason(items[index].StateReason)
		if kind == "" {
			return false, "", nil
		}
		if index == 0 {
			firstKind = kind
		} else {
			secondKind = kind
		}
	}
	blocked, err := s.db.ProjectAssetWorkBlocked(ctx, projectID, assetID)
	if err != nil || blocked {
		return false, "", err
	}
	label := accessBlockKindLabel(firstKind)
	if secondKind != firstKind {
		label = accessBlockKindLabel(firstKind) + "、" + accessBlockKindLabel(secondKind)
	}
	lastResult := truncateProjectText(items[0].Result, projectToolLongText)
	reason := fmt.Sprintf(
		"资产连续 %d 次访问受阻（%s），已停止该资产全部待办意图。触发测试：%s、%s。最后一次结论：%s",
		assetAccessBlockLimit,
		label,
		items[1].ID,
		items[0].ID,
		orDefaultProjectToolValue(lastResult, "未记录详细结论"),
	)
	count, err := s.db.BlockProjectAssetForAccessFailure(
		ctx,
		projectID,
		userID,
		assetID,
		reason,
	)
	if err != nil {
		return false, "", err
	}
	if count == 0 {
		return false, "", nil
	}
	s.auditAssetWork(ctx, "asset_work.access_blocked", assetID, reason)
	stopped := s.StopAssetWorkers(projectID, assetID, reason)
	if stopped > 0 {
		s.auditAssetWork(
			ctx,
			"asset_work.workers_stopped",
			assetID,
			fmt.Sprintf("资产级阻断后停止 %d 个运行中的 Worker", stopped),
		)
	}
	return true, fmt.Sprintf("已阻断该资产 %d 个未完成意图，停止 %d 个 Worker；%s", count, stopped, reason), nil
}

func validateWorkerHypothesisAccess(ctx context.Context, item *database.ProjectTestResult) error {
	if item == nil {
		return fmt.Errorf("测试假设不存在")
	}
	info, ok := execctx.Subagent(ctx)
	if !ok {
		return nil
	}
	kind := strings.ToLower(strings.TrimSpace(info.Kind))
	if kind != "worker" && kind != "subagent" {
		return nil
	}
	hypothesisID := strings.TrimSpace(info.HypothesisID)
	if kind == "worker" && hypothesisID == "" {
		return fmt.Errorf("当前 Worker 缺少测试假设上下文")
	}
	if hypothesisID != "" && hypothesisID != strings.TrimSpace(item.ID) {
		return fmt.Errorf("当前 Worker 不能操作其他测试假设")
	}
	if intentID := strings.TrimSpace(info.IntentID); intentID != "" &&
		strings.TrimSpace(item.IntentID) != "" &&
		intentID != strings.TrimSpace(item.IntentID) {
		return fmt.Errorf("当前 Worker 不能操作其他意图下的测试假设")
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if conversationID != "" && strings.TrimSpace(item.OriginConversationID) != "" &&
		conversationID != strings.TrimSpace(item.OriginConversationID) {
		return fmt.Errorf("测试假设属于其他会话")
	}
	return nil
}

func isUploadAuditHypothesis(item database.ProjectTestResult) bool {
	dimension := strings.ToLower(strings.TrimSpace(item.Dimension))
	technique := strings.ToLower(strings.TrimSpace(item.Technique))
	if strings.Contains(dimension, "上传") || strings.Contains(dimension, "upload") {
		return true
	}
	if strings.Contains(technique, "文件上传") || strings.Contains(technique, "file upload") {
		return true
	}
	return len(highRiskUploadEntries(item.Dimension+"\n"+item.Technique)) > 0
}

func validateUploadCleanEvidence(
	result string,
	evidence string,
	refs []string,
) error {
	text := strings.ToLower(strings.TrimSpace(result + "\n" + evidence))
	checks := []struct {
		label   string
		markers []string
	}{
		{
			label:   "Sink（SaveAs/FileStream/File.Move/File.Copy/WriteAllBytes）",
			markers: []string{"saveas", "filestream", "file.move", "file.copy", "writeallbytes", "appendalltext"},
		},
		{
			label:   "Source（Request.Files/HttpPostedFile/FileName）",
			markers: []string{"request.files", "httppostedfile", "get_filename", "filename", "iformfile"},
		},
		{
			label:   "鉴权判断（鉴权/认证/Token/Session/未授权/匿名）",
			markers: []string{"鉴权", "认证", "token", "session", "未授权", "匿名", "登录"},
		},
		{
			label:   "路径与根目录约束（路径/目录/文件名/GetFullPath/Path.Combine/MapPath）",
			markers: []string{"路径", "根目录", "文件名", "目录", "getfullpath", "path.combine", "mappath"},
		},
		{
			label:   "扩展名或内容校验（扩展名/白名单/Content-Type/magic）",
			markers: []string{"扩展名", "白名单", "content-type", "magic", "后缀"},
		},
	}
	missing := make([]string, 0, len(checks)+2)
	for _, check := range checks {
		found := false
		for _, marker := range check.markers {
			if strings.Contains(text, marker) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, check.label)
		}
	}
	if !uploadEvidenceLocatorPattern.MatchString(text) {
		missing = append(missing, "方法级定位（IL_xxxx、rva=0x...、文件:行号）")
	}
	hasStrongRef := false
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "artifact:") || strings.HasPrefix(ref, "tool:") {
			hasStrongRef = true
			break
		}
	}
	if !hasStrongRef {
		missing = append(missing, "artifact/tool 证据引用")
	}
	authRisk := containsAnyMarker(text,
		"未发现鉴权", "未发现认证", "未发现 token", "未发现 session",
		"无鉴权", "无认证", "无 token", "没有鉴权", "缺少鉴权", "未授权", "匿名访问", "auth_check_found=false",
	)
	fileWrite := containsAnyMarker(text, "saveas", "filestream", "file.move", "file.copy", "writeallbytes")
	clientName := containsAnyMarker(text, "request.files.filename", "httppostedfile.filename", "原始文件名", "get_filename")
	if authRisk && fileWrite && clientName {
		missing = append(missing, "证据已显示未授权文件写入，应改为 suspicious/confirmed，不能 tested_clean")
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"上传类 tested_clean 证据不足，缺少：%s。请在未完成方法级取证时使用 suspicious 或 blocked",
			strings.Join(missing, "、"),
		)
	}
	return nil
}

func containsAnyMarker(text string, markers ...string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// RequalifyLegacyUploadCleanHypotheses 对历史上传类 tested_clean 重新执行证据门禁。
func (s *Service) RequalifyLegacyUploadCleanHypotheses(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	items, err := s.db.ListProjectTestResultsByStatus(ctx, "tested_clean", 10000)
	if err != nil {
		return 0, err
	}
	requalified := 0
	for index := range items {
		item := items[index]
		if !isUploadAuditHypothesis(item) {
			continue
		}
		if err := validateUploadCleanEvidence(item.Result, item.Evidence, item.EvidenceRefs); err == nil {
			continue
		} else {
			notice := "[证据门禁复核] " + err.Error()
			item.Status = "suspicious"
			item.Result = truncateProjectText(strings.TrimSpace(item.Result+"\n\n"+notice), projectToolLongText)
			item.Evidence = truncateProjectText(strings.TrimSpace(item.Evidence+"\n\n"+notice), projectToolLongText)
			if item.Confidence > 60 {
				item.Confidence = 60
			}
			item.UpdatedAt = time.Now().UTC()
			if _, err := s.db.UpsertProjectTestResult(ctx, item); err != nil {
				return requalified, err
			}
			requalified++
		}
	}
	return requalified, nil
}

func (s *Service) seedFollowUpHypotheses(
	ctx context.Context,
	projectID string,
	finding database.Vulnerability,
) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(finding.ID) == "" ||
		!shouldGenerateFollowUps(finding) {
		return
	}
	maxHypotheses := s.configSnapshot().AgentMaxHypotheses
	items := buildFollowUpHypotheses(finding)
	if maxHypotheses > 0 {
		total, err := s.db.CountProjectHypotheses(ctx, projectID)
		if err != nil || total >= maxHypotheses {
			return
		}
		remaining := maxHypotheses - total
		if len(items) > remaining {
			items = items[:remaining]
		}
	}
	active, err := s.db.ListActiveProjectHypotheses(ctx, projectID)
	if err != nil {
		return
	}
	refs := make([]hypothesisDimensionRef, 0, len(active))
	for _, item := range active {
		refs = append(refs, hypothesisDimensionRef{
			AssetID:   item.AssetID,
			Dimension: item.Dimension,
		})
	}
	for index := range items {
		if overlappingHypothesisIndex(refs, items[index].AssetID, items[index].Dimension) >= 0 {
			continue
		}
		items[index].ProjectID = projectID
		if _, err := s.db.UpsertProjectTestResult(ctx, items[index]); err == nil {
			refs = append(refs, hypothesisDimensionRef{
				AssetID:   items[index].AssetID,
				Dimension: items[index].Dimension,
			})
		}
	}
}

func shouldGenerateFollowUps(finding database.Vulnerability) bool {
	switch strings.ToLower(strings.TrimSpace(finding.Status)) {
	case "pending_review", "fixed", "false_positive", "ignored", "closed", "dismissed", "resolved":
		return false
	case "confirmed":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(finding.VerificationState)) {
	case "exploitable", "verified":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
	case "critical", "high":
		return true
	default:
		return false
	}
}

func buildFollowUpHypotheses(finding database.Vulnerability) []database.ProjectTestResult {
	now := time.Now().UTC()
	assetID := strings.TrimSpace(finding.AssetID)
	if assetID == "" {
		return nil
	}
	vulnType := strings.ToLower(strings.TrimSpace(finding.VulnerabilityType + " " + finding.Title))
	type candidate struct {
		dimension string
		technique string
		reason    string
		expected  string
		priority  int
	}
	candidates := make([]candidate, 0, maxFollowUpPerFinding)
	switch {
	case strings.Contains(vulnType, "sql"):
		candidates = []candidate{
			{"SQL注入", "time-based", "验证时间盲注，补充 boolean/error 之外的可利用路径", "可重复的响应延时差异", 88},
			{"SQL注入", "stacked-query", "确认数据库驱动是否允许多语句执行", "第二条 SQL 语句产生可观测副作用", 78},
			{"SQL注入", "out-of-band", "验证带外读取或 DNS/HTTP 回连能力", "目标发起可识别的带外请求", 74},
			{"参数变体", "adjacent-parameter", "检查同一接口的其他参数是否存在同类缺陷", "其他参数出现 SQL 差异回显", 82},
			{"权限上下文", "auth-context", "比较匿名、低权限和管理员身份的注入表现", "不同权限下出现稳定差异", 76},
		}
	case strings.Contains(vulnType, "xss"):
		candidates = []candidate{
			{"XSS", "stored", "确认输入是否在其他页面持久化执行", "二次访问触发脚本执行", 88},
			{"XSS", "dom", "检查前端 JavaScript 是否消费危险参数", "DOM 节点执行可控内容", 82},
			{"XSS", "encoding-bypass", "验证 HTML、URL、JS 多层编码绕过", "绕过现有过滤并执行脚本", 80},
			{"权限上下文", "auth-context", "检查不同角色和登录状态下的输出差异", "不同权限下出现稳定 XSS 差异", 74},
		}
	case strings.Contains(vulnType, "ssrf"):
		candidates = []candidate{
			{"SSRF", "dns", "验证 DNS 回连能力", "目标产生可识别的 DNS 查询", 88},
			{"SSRF", "file", "检查本地文件读取协议", "返回本地文件内容或错误特征", 84},
			{"SSRF", "internal-network", "探测可达的内网服务和云元数据", "内网服务或元数据端点返回响应", 90},
			{"编码绕过", "encoding-bypass", "测试协议和地址编码绕过", "绕过 URL 校验并触发请求", 80},
		}
	default:
		candidates = []candidate{
			{"参数变体", "adjacent-parameter", "检查相邻参数和同接口其他入口", "发现同类或更强缺陷", 75},
			{"权限上下文", "auth-context", "验证匿名、普通用户和管理员身份差异", "权限边界被绕过", 78},
			{"编码绕过", "encoding-bypass", "测试过滤器与 WAF 绕过变体", "过滤规则被稳定绕过", 74},
			{"链式利用", "exploit-chain", "评估与现有凭据、上传或 SSRF 的联动", "形成可验证的攻击链", 82},
		}
	}
	items := make([]database.ProjectTestResult, 0, len(candidates))
	for _, item := range candidates {
		if strings.EqualFold(strings.TrimSpace(item.technique), strings.TrimSpace(finding.TestTechnique)) {
			continue
		}
		items = append(items, database.ProjectTestResult{
			ProjectID: finding.ProjectID,
			AssetID:   assetID,
			Dimension: item.dimension,
			Technique: item.technique,
			Status:    "untested",
			Rationale: item.reason,
			Expected:  item.expected,
			Priority:  item.priority,
			ParentID:  finding.ID,
			Required:  false,
			CreatedAt: now,
		})
		if len(items) >= maxFollowUpPerFinding {
			break
		}
	}
	return items
}

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
