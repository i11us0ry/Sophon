package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

// projectWritebackGuidance 只说明可用的项目工具能力，不规定执行顺序。
const projectWritebackGuidance = `

项目工具能力（按需使用，不是完成条件）：
- project_* 工具可读取或维护当前项目的资产、事实、测试、漏洞、审计记录、意图、目标和攻击链。
- 需要完整上下文时可使用 project_list(resource=facts/findings) 或 project_get(resource=graph_node) 读取明细。
- 工具参数以实际 schema 为准；是否使用、何时使用和执行顺序由你根据用户请求决定。`

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
			age := formatSituationAge(currentIntent.UpdatedAt)
			if age != "" {
				age = "，已持续 " + age
			}
			builder.WriteString(fmt.Sprintf(
				"当前意图：[%s] %s（id %s%s）\n",
				currentIntent.Status,
				currentIntent.Title,
				currentIntent.ID,
				age,
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
				age := formatSituationAge(node.UpdatedAt)
				if age != "" {
					age = "，已持续 " + age
				}
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s（id %s%s）\n",
					node.Status,
					truncateProjectText(node.Title, situationTextRune),
					node.ID,
					age,
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
	if workspace := s.auditWorkspaceSituation(projectID, conversationID); workspace != "" {
		builder.WriteString(workspace)
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
		builder.WriteString("关键约束记忆（仅作为上下文）：\n")
		for index, fact := range criticalFacts {
			if index >= situationFactIndexLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 条关键约束记忆）\n", len(criticalFacts)-situationFactIndexLimit))
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

	// 覆盖率与候选目标只作为项目状态，不规定 Agent 的下一步动作。
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
			attachments, _ := s.db.ListRecentProjectAttachments(ctx, projectID, userID, 1)
			if len(attachments) > 0 {
				builder.WriteString("- 项目已有上传附件，但尚未登记网络资产。附件可作为源码或其他分析材料。\n")
			} else {
				builder.WriteString("- 项目资产数：0。\n")
			}
		}
		if assetID != "" {
			builder.WriteString("候选目标：当前任务已绑定资产，当前资产明细以上方资产卡片为准。\n")
		} else if len(coverage.NextTargets) == 0 {
			builder.WriteString("候选目标（可用 project_next_targets 查看明细）：\n- 无\n")
		} else {
			builder.WriteString("候选目标（可用 project_next_targets 查看明细）：\n")
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
	testedCells := make([]database.ProjectFact, 0)
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
			} else if status == "tested" {
				testedCells = append(testedCells, *fact)
			}
		}
	}
	sort.SliceStable(testedCells, func(i, j int) bool {
		return testedCells[i].UpdatedAt.After(testedCells[j].UpdatedAt)
	})
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
		for index, fact := range testedCells {
			if index >= situationFailureLimit {
				builder.WriteString(fmt.Sprintf("- …（另有 %d 个已测试单元格）\n", len(testedCells)-situationFailureLimit))
				break
			}
			builder.WriteString("- TESTED：")
			builder.WriteString(truncateProjectText(fact.SubjectKey, situationTextRune))
			if conclusion, result := auditCellConclusion(fact.Body); conclusion != "" || result != "" {
				builder.WriteString("；")
				if conclusion != "" {
					builder.WriteString(conclusion)
				}
				if result != "" {
					if conclusion != "" {
						builder.WriteString("：")
					}
					builder.WriteString(truncateProjectText(result, situationFactSummaryRune))
				}
			}
			builder.WriteString("\n")
		}
	}
	if checkpoint != nil {
		builder.WriteString("- 最近断点：")
		builder.WriteString(truncateProjectText(projectFactSummary(*checkpoint), situationTextRune))
		if body := strings.TrimSpace(checkpoint.Body); body != "" {
			var details struct {
				Completed []string `json:"completed_directions"`
				RuledOut  []string `json:"ruled_out_directions"`
				Pending   []string `json:"pending_directions"`
				Evidence  []string `json:"evidence_refs"`
			}
			if json.Unmarshal([]byte(body), &details) == nil {
				if len(details.Completed) > 0 {
					builder.WriteString("；已完成=")
					builder.WriteString(truncateProjectText(strings.Join(details.Completed, "、"), situationTextRune))
				}
				if len(details.RuledOut) > 0 {
					builder.WriteString("；已排除=")
					builder.WriteString(truncateProjectText(strings.Join(details.RuledOut, "、"), situationTextRune))
				}
				if len(details.Pending) > 0 {
					builder.WriteString("；待处理=")
					builder.WriteString(truncateProjectText(strings.Join(details.Pending, "、"), situationTextRune))
				}
				if len(details.Evidence) > 0 {
					builder.WriteString("；证据=")
					builder.WriteString(truncateProjectText(strings.Join(details.Evidence, "、"), situationTextRune))
				}
			} else {
				builder.WriteString("；")
				builder.WriteString(truncateProjectText(body, situationTextRune))
			}
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

func formatSituationAge(updated time.Time) string {
	if updated.IsZero() {
		return ""
	}
	age := time.Since(updated)
	if age < time.Minute {
		return "刚刚"
	}
	if age < time.Hour {
		return fmt.Sprintf("%d分钟", int(age.Minutes()))
	}
	if age < 24*time.Hour {
		return fmt.Sprintf("%d小时", int(age.Hours()))
	}
	return fmt.Sprintf("%d天", int(age.Hours()/24))
}

func (s *Service) auditWorkspaceSituation(projectID, conversationID string) string {
	conversationID = strings.TrimSpace(conversationID)
	if s == nil || conversationID == "" {
		return ""
	}
	paths, err := s.agentWorkspacePathsFor(projectID, conversationID)
	if err != nil {
		return ""
	}
	for _, workspace := range []string{paths.ConversationRoot, paths.LegacyRoot} {
		entries, readErr := os.ReadDir(workspace)
		if readErr != nil {
			continue
		}
		if rendered := formatAuditWorkspaceSituation(workspace, entries); rendered != "" {
			return rendered
		}
	}
	return ""
}

func formatAuditWorkspaceSituation(workspace string, entries []os.DirEntry) string {
	artifacts := make([]string, 0, 8)
	auditEntries := 0
	for _, entry := range entries {
		name := entry.Name()
		lower := strings.ToLower(name)
		if entry.IsDir() {
			switch lower {
			case "audit_out":
				if children, readErr := os.ReadDir(filepath.Join(workspace, name)); readErr == nil {
					auditEntries = len(children)
				}
				artifacts = append(artifacts, name+"/")
			case "audit_extract", "webxml", "dbstep":
				artifacts = append(artifacts, name+"/")
			}
			continue
		}
		if !(strings.HasPrefix(lower, "sink_") ||
			strings.HasPrefix(lower, "cand_") ||
			lower == "jar_versions.txt") {
			continue
		}
		size := int64(0)
		if info, infoErr := entry.Info(); infoErr == nil {
			size = info.Size()
		}
		artifacts = append(artifacts, fmt.Sprintf("%s（%dKB）", name, max(1, int(size/1024))))
	}
	if len(artifacts) == 0 {
		return ""
	}
	sort.Strings(artifacts)

	var builder strings.Builder
	builder.WriteString("\nJava 审计工作台（已有文件优先复用，不要重新考古）：\n")
	for index, artifact := range artifacts {
		if index >= 8 {
			builder.WriteString(fmt.Sprintf("- …（另有 %d 项）\n", len(artifacts)-8))
			break
		}
		builder.WriteString("- " + artifact + "\n")
	}
	if auditEntries > 0 {
		builder.WriteString(fmt.Sprintf("audit_out/ 当前包含 %d 个条目。\n", auditEntries))
	}
	builder.WriteString("先消费候选索引、路由和鉴权产物，再按当前 intent 收敛；已否定的方向先更新旧 intent，不要重新当成待办。\n")
	return builder.String()
}

func auditCellConclusion(body string) (string, string) {
	var details struct {
		Conclusion string `json:"conclusion_state"`
		Result     string `json:"result"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &details) != nil {
		return "", ""
	}
	return strings.TrimSpace(details.Conclusion), strings.TrimSpace(details.Result)
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
