package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	situationGoalLimit       = 5
	situationIntentLimit     = 10
	situationTodoLimit       = 10
	situationCredentialLimit = 10
	situationFactIndexLimit  = 12
	situationFindingLimit    = 10
	situationAssetLimit      = 15
	situationFailureLimit    = 5
	situationProbeLimit      = 10
	situationFactSummaryRune = 120
	situationTextRune        = 180
	situationTotalRunes      = 7000
)

// projectWritebackGuidance 是注入主 Agent 与子 Agent 的写回纪律（对齐 Sophon 的「边渗透边记录」）。
const projectWritebackGuidance = `

项目写回纪律（强制）：
- 新域名、IP、URL、端口或主机立即用 project_insert_assets 登记，类型只能是 domain/ip/url/port/host。
- 一个主题只维护一条事实，使用稳定 category/slug key，只写新增认知；事实存环境与攻击链，测试结果用 project_record_test，可交付漏洞用 project_report_finding。
- 测试前用 project_plan_hypotheses 建假设；Worker 用 project_start_hypothesis 领取，用 project_complete_hypothesis 完成。达到假设上限后只写事实和测试结果。
- 每项测试后用 project_record_test 写结论和 evidence_refs（tool:/fact:/artifact:/conversation:）；未发现漏洞也必须写 tested_clean 和负向证据。
- 确认漏洞先用 project_report_finding 写规范 vulnerability_type、title_impact、description、preconditions、完整 poc/HTTP 数据包、evidence、impact、recommendation、residual_notes 和 asset_id；证据必填，复测备注无则写“无”，复现步骤末尾必须包含“利用脚本（优先 Python）”及 Python 代码块；高危以上缺任一字段或 PoC 不完整时不得上报。
- 主动验证的测试结果、漏洞证据或复测备注必须记录适用的 WP-1 等价表达覆盖、WP-2 最小必要条件、WP-3 外部先验与根因映射；不适用项写原因，禁止只写“已检查”。
- 代码审计先用 project_record_audit(action=scope) 写明纳入和排除类别；按 service×entry×shape×surface 建矩阵，未测单元格记 not_audited，实测后回写 tested/not_applicable。零记录只能写未审计，不得写成已排除。
- 发现漏检形态后用 project_record_audit(action=rescan) 生成同类跨分发面回扫单元；阶段切换或中断前用 action=checkpoint 写下一步首个动作。
- 收尾先清除或说明 not_audited 单元格，并抽查一条 tested_clean 旧结论的证据是否仍成立。
- 新攻击方向先 project_add_intent，完成后 project_update_intent；目标达成或失效时更新 project_update_goal。
- 摘要只作索引，需要全文时调用 project_list(resource=facts/findings) 或 project_get(resource=graph_node)。`

func (s *Service) projectSituation(ctx context.Context, projectID, userID string) string {
	return s.projectSituationForContext(ctx, projectID, userID, "")
}

// projectSituationForContext 生成每轮注入的任务态势包。
// 参考黑板索引与图谱概览设计：只给状态和索引，明细按需调用工具。
func (s *Service) projectSituationForContext(
	ctx context.Context,
	projectID string,
	userID string,
	conversationID string,
) string {
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	if s.db == nil || projectID == "" || userID == "" {
		return ""
	}
	assetID := strings.TrimSpace(execctx.AssetID(ctx))
	var builder strings.Builder
	builder.WriteString("\n\n当前项目任务态势包：\n")
	if execution, ok := missionExecutionFromContext(ctx); ok {
		builder.WriteString("服务端任务意图：\n")
		builder.WriteString("- 模式：" + execution.Plan.Mode + "\n")
		builder.WriteString("- 阶段：" + execution.Phase + "\n")
		if len(execution.Plan.Tasks) > 0 {
			builder.WriteString("- 任务顺序：" + strings.Join(execution.Plan.Tasks, " -> ") + "\n")
		}
		if stages := execution.Plan.missionStages(); len(stages) > 0 {
			builder.WriteString("- 阶段顺序：" + strings.Join(stages, " -> ") + "\n")
		}
		if len(execution.Plan.SourceRoots) > 0 {
			builder.WriteString("- 源码范围：" + strings.Join(execution.Plan.SourceRoots, "、") + "\n")
		}
		if len(execution.Plan.VulnerabilityIDs) > 0 {
			builder.WriteString("- 复测漏洞：" + strings.Join(execution.Plan.VulnerabilityIDs, "、") + "\n")
		}
		if len(execution.Plan.RetestIDs) > 0 {
			builder.WriteString("- 复测任务：" + strings.Join(execution.Plan.RetestIDs, "、") + "\n")
		}
		if len(execution.Plan.AppArtifacts) > 0 {
			builder.WriteString("- App 包：" + strings.Join(execution.Plan.AppArtifacts, "、") + "\n")
		}
		if execution.Plan.allowsPentest() {
			builder.WriteString("- 明确渗透目标：" + formatMissionTargets(execution.Plan) + "\n")
		} else if missionStageAllowsNetwork(execution.Phase) &&
			len(execution.Plan.PentestTargets) > 0 {
			builder.WriteString("- 明确运行时验证目标：" + formatMissionTargets(execution.Plan) + "\n")
		} else {
			builder.WriteString("- 后续出现的项目目标、未完成意图和探测记录仅作为背景，不属于本轮执行范围\n")
		}
		if execution.Plan.Mode == missionModeProjectWrite && len(execution.Plan.WriteTools) > 0 {
			builder.WriteString("- 允许的项目写工具：" + strings.Join(execution.Plan.WriteTools, "、") + "\n")
		}
		builder.WriteString("- 完成条件：完成用户请求的当前任务后立即结束，不扩展到其他资产\n")
	}
	if assetID != "" {
		if card, err := s.renderProjectAssetCard(ctx, projectID, userID, assetID); err == nil {
			builder.WriteString(card)
			builder.WriteString("\n")
		} else {
			builder.WriteString("当前资产卡片：读取失败，请调用 project_get（resource=asset）重试\n")
		}
	}

	var nodes []database.GraphNode
	if items, err := s.db.ListProjectGraphNodesByAsset(ctx, projectID, assetID); err == nil {
		nodes = items
		goals := make([]database.GraphNode, 0, situationGoalLimit)
		intents := make([]database.GraphNode, 0, situationIntentLimit)
		for _, node := range nodes {
			switch node.Kind {
			case "goal":
				goals = append(goals, node)
			case "intent":
				intents = append(intents, node)
			}
		}
		sortGraphNodesByUpdated(goals)
		sortGraphNodesByUpdated(intents)
		if len(goals) > 0 {
			builder.WriteString("目标：\n")
			for index, node := range goals {
				if index >= situationGoalLimit {
					builder.WriteString(fmt.Sprintf("- …（另有 %d 个目标）\n", len(goals)-situationGoalLimit))
					break
				}
				builder.WriteString(fmt.Sprintf("- %s（%s）\n", node.Title, node.Status))
			}
		} else {
			builder.WriteString("目标：暂无明确目标节点\n")
		}

		currentIntent, hasCurrent := selectCurrentIntent(intents)
		if hasCurrent {
			builder.WriteString(fmt.Sprintf(
				"当前意图：[%s] %s（id %s）\n",
				currentIntent.Status,
				currentIntent.Title,
				currentIntent.ID,
			))
		} else {
			builder.WriteString("当前意图：无运行中或开放意图\n")
		}

		todos := pendingIntentTodos(intents, currentIntent.ID, hasCurrent)
		builder.WriteString(fmt.Sprintf("Todo（未完成意图，共 %d 条）：\n", len(todos)))
		if len(todos) == 0 {
			builder.WriteString("- 无\n")
		} else {
			for index, node := range todos {
				if index >= situationTodoLimit {
					builder.WriteString(fmt.Sprintf("- …（另有 %d 条）\n", len(todos)-situationTodoLimit))
					break
				}
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s（id %s）\n",
					node.Status,
					truncateProjectText(node.Title, situationTextRune),
					node.ID,
				))
			}
		}
	}
	if strings.TrimSpace(conversationID) != "" {
		groups := buildProbeLedger(
			s.recentProbeExecutions(ctx, conversationID),
			situationProbeLimit,
		)
		builder.WriteString("最近网络探测账本（最近 90 分钟，按 Host/Path/Method 聚合）：\n")
		builder.WriteString(formatProbeLedger(groups))
	}

	credentials := make([]database.ProjectFact, 0)
	facts := make([]database.ProjectFact, 0)
	if items, err := s.db.ListProjectFactsByAsset(ctx, projectID, assetID); err == nil {
		for _, fact := range items {
			if isCredentialFact(fact) {
				credentials = append(credentials, fact)
			} else {
				facts = append(facts, fact)
			}
		}
	}
	// 事实索引按「相关度 + 重要度 + 时间衰减」召回，而不是按更新时间截断。
	rankedFacts := facts
	if len(facts) > 0 {
		query := ""
		if messages, err := s.db.GetMessages(ctx, conversationID, 20); err == nil {
			for index := len(messages) - 1; index >= 0; index-- {
				if strings.EqualFold(strings.TrimSpace(messages[index].Role), "user") {
					query = messages[index].Content
					break
				}
			}
		}
		ranked := s.rankProjectFacts(ctx, query, facts)
		rankedFacts = make([]database.ProjectFact, 0, len(ranked))
		for _, item := range ranked {
			rankedFacts = append(rankedFacts, item.Fact)
		}
		s.touchMemoryUsage(rankedFacts)
	}

	builder.WriteString(fmt.Sprintf("已知凭据与账号（共 %d 条）：\n", len(credentials)))
	if len(credentials) == 0 {
		builder.WriteString("- 无\n")
	} else {
		for index, fact := range credentials {
			if index >= situationCredentialLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条）\n", len(credentials)-situationCredentialLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- %s：%s（置信度 %d%%）\n",
				fact.Key,
				truncateProjectText(projectFactBody(fact), situationFactSummaryRune),
				fact.Confidence,
			))
		}
	}

	criticalFacts := make([]database.ProjectFact, 0)
	for _, fact := range rankedFacts {
		if isAuditCellFact(fact) {
			continue
		}
		if fact.Pinned || fact.Priority >= 85 || memoryKindScore(fact) >= 0.9 {
			criticalFacts = append(criticalFacts, fact)
		}
	}
	if len(criticalFacts) > 0 {
		builder.WriteString("强制记忆（必须优先遵守）：\n")
		for index, fact := range criticalFacts {
			if index >= situationFactIndexLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条强制记忆）\n", len(criticalFacts)-situationFactIndexLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s] %s: %s（优先级 %d，置信度 %d%%）\n",
				fact.MemoryKind,
				fact.Key,
				truncateProjectText(projectFactSummary(fact), situationFactSummaryRune),
				fact.Priority,
				fact.Confidence,
			))
		}
	}

	builder.WriteString("事实索引（需要全文调用 project_list(resource=\"facts\")）：\n")
	if len(facts) == 0 {
		builder.WriteString("- 无\n")
	} else {
		for index, fact := range rankedFacts {
			if index >= situationFactIndexLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条事实未列出）\n", len(facts)-situationFactIndexLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s] %s: %s（置信度 %d%%）\n",
				fact.FactType,
				fact.Key,
				truncateProjectText(projectFactSummary(fact), situationFactSummaryRune),
				fact.Confidence,
			))
		}
	}
	builder.WriteString(s.auditLedgerSituation(ctx, projectID, facts))

	if conflicts, conflictErr := s.db.ListProjectFactConflicts(ctx, projectID, situationFindingLimit); conflictErr == nil && len(conflicts) > 0 {
		builder.WriteString("未解决事实冲突（不得当作确定结论）：\n")
		for index, fact := range conflicts {
			if index >= situationFailureLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条冲突）\n", len(conflicts)-situationFailureLimit))
				break
			}
			builder.WriteString(fmt.Sprintf(
				"- %s：%s（与 %s 冲突，优先级 %d）\n",
				fact.Key,
				truncateProjectText(projectFactSummary(fact), situationFactSummaryRune),
				fact.ContradictedBy,
				fact.Priority,
			))
		}
	}
	if entities, entityErr := s.db.ListProjectMemoryEntities(ctx, projectID, "", 200); entityErr == nil {
		builder.WriteString(fmt.Sprintf("结构化记忆实体：%d 个（需要关系调用 project_memory_graph）\n", len(entities)))
	}

	findings, total, err := s.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: userID,
		ProjectID:   projectID,
		AssetID:     assetID,
		Limit:       situationFindingLimit,
	})
	if err == nil && len(findings) > 0 {
		builder.WriteString(fmt.Sprintf("漏洞摘要（共 %d 条，需要明细调用 project_list(resource=\"findings\")）：\n", total))
		for _, item := range findings {
			target := ""
			if value := strings.TrimSpace(item.Target); value != "" {
				target = " target=" + truncateProjectText(value, 100)
			}
			builder.WriteString(fmt.Sprintf(
				"- [%s/%s/%s] %s%s（id %s）\n",
				item.Severity,
				item.Status,
				item.VerificationState,
				truncateProjectText(item.Title, 140),
				target,
				item.ID,
			))
		}
	} else {
		builder.WriteString("漏洞摘要：无\n")
	}

	// 覆盖率与未覆盖队列：直接驱动 Agent 优先处理未覆盖目标（资产/意图/证据缺口）。
	if coverage, coverageErr := s.db.ProjectCoverage(ctx, projectID, userID); coverageErr == nil {
		builder.WriteString(fmt.Sprintf(
			"覆盖率：资产观测 %d/%d（%.0f%%），完整覆盖 %d/%d（%.0f%%），部分覆盖 %d，阻断 %d，可疑 %d，未测试资产 %d，测试 %d/%d（%.0f%%），必需/可选未完成测试 %d/%d，可疑测试 %d，证据缺口 %d，待办/运行意图 %d/%d\n",
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
		if coverage.AssetsTotal == 0 {
			builder.WriteString("- 资产登记缺失：当前项目 0 个资产。本轮如使用目标工具，必须先调用 project_insert_assets 登记目标。\n")
		}
		builder.WriteString("调度规则：优先处理未测试资产；同一 Host/Path/Method 未产生新证据时禁止原样重跑；一个目标写回测试结果后再切换下一个目标。\n")
		if assetID != "" {
			builder.WriteString("未覆盖队列：当前任务已绑定资产，跨资产队列不注入；当前资产明细以上方资产卡片为准。\n")
		} else if len(coverage.NextTargets) == 0 {
			builder.WriteString("未覆盖队列（按优先级，需要明细调用 project_next_targets）：\n- 无，所有已知目标均已覆盖\n")
		} else {
			builder.WriteString("未覆盖队列（按优先级，需要明细调用 project_next_targets）：\n")
			for index, target := range coverage.NextTargets {
				if index >= situationAssetLimit {
					builder.WriteString(fmt.Sprintf("- …（另有 %d 项）\n", len(coverage.NextTargets)-situationAssetLimit))
					break
				}
				if assetID != "" && target.Kind == "asset" && target.RefID != assetID {
					continue
				}
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s — %s（优先级 %d）\n",
					target.Kind,
					truncateProjectText(target.Label, situationTextRune),
					target.Reason,
					target.Score,
				))
			}
		}
	} else {
		builder.WriteString("覆盖率：统计暂不可用\n")
	}

	if strings.TrimSpace(conversationID) != "" {
		failures, failureErr := s.db.ListRecentFailedToolExecutions(
			ctx,
			conversationID,
			situationFailureLimit,
		)
		builder.WriteString("最近失败工具（当前会话）：\n")
		if failureErr != nil || len(failures) == 0 {
			builder.WriteString("- 无\n")
		} else {
			for _, failure := range failures {
				message := strings.TrimSpace(failure.Error)
				if message == "" {
					message = "执行失败"
				}
				builder.WriteString(fmt.Sprintf(
					"- %s：%s（%s）\n",
					failure.ToolName,
					truncateProjectText(message, situationTextRune),
					failure.StartedAt.Format("15:04:05"),
				))
			}
		}
	}
	if campaignID := strings.TrimSpace(execctx.CampaignID(ctx)); campaignID != "" {
		if digests, digestErr := s.db.ListCampaignMemoryDigests(
			ctx,
			campaignID,
			database.CampaignMemoryTierHot,
			5,
		); digestErr == nil && len(digests) > 0 {
			builder.WriteString("战役长期记忆（热）：\n")
			for _, digest := range digests {
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s\n",
					digest.Kind,
					truncateProjectText(digest.Summary, situationFactSummaryRune),
				))
			}
		}
	}
	return truncateProjectText(builder.String(), situationTotalRunes)
}

func (s *Service) auditLedgerSituation(
	ctx context.Context,
	projectID string,
	facts []database.ProjectFact,
) string {
	var scope *database.ProjectFact
	var checkpoint *database.ProjectFact
	cellCounts := map[string]int{}
	notAudited := make([]database.ProjectFact, 0)
	for index := range facts {
		fact := &facts[index]
		switch fact.SubjectType {
		case auditSubjectScope:
			if scope == nil || fact.UpdatedAt.After(scope.UpdatedAt) {
				scope = fact
			}
		case auditSubjectCheckpoint:
			if checkpoint == nil || fact.UpdatedAt.After(checkpoint.UpdatedAt) {
				checkpoint = fact
			}
		case auditSubjectCell:
			status := strings.ToLower(strings.TrimSpace(fact.ObjectKey))
			cellCounts[status]++
			if status == "not_audited" {
				notAudited = append(notAudited, *fact)
			}
		}
	}
	var builder strings.Builder
	if scope != nil || len(cellCounts) > 0 || checkpoint != nil {
		builder.WriteString("审计台账：\n")
	}
	if scope != nil {
		builder.WriteString("- 范围：")
		builder.WriteString(truncateProjectText(projectFactSummary(*scope), situationTextRune))
		builder.WriteString("\n")
	}
	if len(cellCounts) > 0 {
		builder.WriteString(fmt.Sprintf(
			"- 覆盖矩阵：tested %d，not_audited %d，not_applicable %d\n",
			cellCounts["tested"],
			cellCounts["not_audited"],
			cellCounts["not_applicable"],
		))
		for index, fact := range notAudited {
			if index >= situationFailureLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 个未审计单元格）\n", len(notAudited)-situationFailureLimit))
				break
			}
			builder.WriteString("- NOT_AUDITED：")
			builder.WriteString(truncateProjectText(fact.SubjectKey, situationTextRune))
			builder.WriteString("\n")
		}
	}
	if checkpoint != nil {
		builder.WriteString("- 最近断点：")
		builder.WriteString(truncateProjectText(projectFactSummary(*checkpoint), situationTextRune))
		if body := strings.TrimSpace(checkpoint.Body); body != "" {
			builder.WriteString("；")
			builder.WriteString(truncateProjectText(body, situationTextRune))
		}
		builder.WriteString("\n")
	}
	if sample := s.oldConclusionReviewCandidate(ctx, projectID); sample != "" {
		builder.WriteString("- 旧结论抽查候选：")
		builder.WriteString(sample)
		builder.WriteString("\n")
	}
	if execution, ok := missionExecutionFromContext(ctx); ok &&
		execution.Plan.Mode == missionModeCodeAudit && scope == nil {
		builder.WriteString("- 审计范围尚未结构化记录；不得把未纳入类别写成已排除。请调用 project_record_audit(action=scope) 写入纳入和排除类别。\n")
	}
	return builder.String()
}

func (s *Service) oldConclusionReviewCandidate(ctx context.Context, projectID string) string {
	if s == nil || s.db == nil || strings.TrimSpace(projectID) == "" {
		return ""
	}
	items, err := s.db.ListProjectTestResults(ctx, projectID, 200)
	if err != nil {
		return ""
	}
	for index := len(items) - 1; index >= 0; index-- {
		item := items[index]
		if item.Status != "tested_clean" {
			continue
		}
		if strings.TrimSpace(item.Evidence) == "" && len(item.EvidenceRefs) == 0 {
			continue
		}
		label := strings.TrimSpace(item.Dimension)
		if technique := strings.TrimSpace(item.Technique); technique != "" {
			label += " / " + technique
		}
		return truncateProjectText(label, situationTextRune) +
			"（更新于 " + item.UpdatedAt.Format("2006-01-02 15:04:05") + "）"
	}
	return ""
}

func sortGraphNodesByUpdated(nodes []database.GraphNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		return nodes[i].UpdatedAt.After(nodes[j].UpdatedAt)
	})
}

func selectCurrentIntent(intents []database.GraphNode) (database.GraphNode, bool) {
	sorted := append([]database.GraphNode(nil), intents...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := intentStatusPriority(sorted[i].Status)
		right := intentStatusPriority(sorted[j].Status)
		if left != right {
			return left < right
		}
		return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt)
	})
	for _, node := range sorted {
		if node.Status == "running" || node.Status == "open" {
			return node, true
		}
	}
	return database.GraphNode{}, false
}

func pendingIntentTodos(
	intents []database.GraphNode,
	currentID string,
	hasCurrent bool,
) []database.GraphNode {
	todos := make([]database.GraphNode, 0, len(intents))
	for _, node := range intents {
		if node.Status != "open" && node.Status != "running" {
			continue
		}
		if hasCurrent && node.ID == currentID {
			continue
		}
		todos = append(todos, node)
	}
	sort.SliceStable(todos, func(i, j int) bool {
		left := intentStatusPriority(todos[i].Status)
		right := intentStatusPriority(todos[j].Status)
		if left != right {
			return left < right
		}
		return todos[i].UpdatedAt.After(todos[j].UpdatedAt)
	})
	return todos
}

func intentStatusPriority(status string) int {
	switch status {
	case "running":
		return 0
	case "open":
		return 1
	default:
		return 2
	}
}

func projectFactSummary(fact database.ProjectFact) string {
	if summary := strings.TrimSpace(fact.Summary); summary != "" {
		return summary
	}
	return strings.TrimSpace(fact.Value)
}

func projectFactBody(fact database.ProjectFact) string {
	if body := strings.TrimSpace(fact.Body); body != "" {
		return body
	}
	return projectFactSummary(fact)
}

func isCredentialFact(fact database.ProjectFact) bool {
	text := strings.ToLower(strings.Join([]string{
		fact.FactType,
		fact.Key,
		projectFactSummary(fact),
		fact.Body,
	}, " "))
	for _, marker := range []string{
		"credential",
		"password",
		"passwd",
		"username",
		"account",
		"凭据",
		"口令",
		"密码",
		"账号",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// projectSituationForConversation 供子 Agent 使用：先按会话解析项目，再生成态势快照。
func (s *Service) projectSituationForConversation(
	ctx context.Context,
	conversationID string,
	userID string,
) string {
	if s.db == nil || strings.TrimSpace(conversationID) == "" || strings.TrimSpace(userID) == "" {
		return ""
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		return ""
	}
	return s.projectSituationForContext(
		ctx,
		conversation.ProjectID,
		userID,
		conversationID,
	)
}
