package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	strategySwitchInterval      = 5
	emptyFinalTextReason        = "最终回答为空：模型只返回了推理或工具调用，尚未生成可交付结论"
	finalizationSynthesisPrompt = `【强制总结轮】工具执行阶段已结束，本轮禁止调用任何工具。
请基于当前任务态势、项目事实、测试结果、漏洞和工具输出，直接生成面向用户的最终文本。
必须包含：
1. 已完成的工作和已验证结论；
2. 关键证据、漏洞及影响；
3. 仅列出真实的外部阻塞（缺少授权、缺少凭据、需要人工审批或目标范围外），不得把内部迭代窗口、Token 或工具次数列为未完成原因；
4. 主动验证任务说明 WP-1 等价空间、WP-2 最小必要条件和 WP-3 外部先验的适用结果；未完成的适用项只能标记未验证，不能输出确定性成功结论；
5. 如仍有未完成方向，应继续执行而不是生成该总结。
不得只输出推理过程、工具计划或空内容。`
)

type finalizationDecision struct {
	Allowed                 bool
	Reasons                 []string
	PendingToolCalls        []string
	HasExternalTools        bool
	EvidenceVerified        bool
	ActiveIntentCount       int
	DerivableBlockedIntents int
	CapacityBlockedIntents  int
	OpenGoalCount           int
	AssetCount              int
	AssetsCovered           int
	AssetsPartial           int
	AssetsUntested          int
	TestTotal               int
	TestCovered             int
	TestOpen                int
	TestOpenOptional        int
	TestSuspicious          int
	UnresolvedConflicts     int
	PendingUserConfirmation bool
	PauseOnQuestion         bool
	ActionableNextTargets   int
	ObjectiveCompleted      bool
	ObjectiveReason         string
}

func requireFinalText(decision finalizationDecision, finalText string) finalizationDecision {
	if strings.TrimSpace(finalText) != "" {
		return decision
	}
	decision.Allowed = false
	for _, reason := range decision.Reasons {
		if reason == emptyFinalTextReason {
			return decision
		}
	}
	decision.Reasons = append(decision.Reasons, emptyFinalTextReason)
	return decision
}

func clearFinalTextRequirement(decision finalizationDecision) finalizationDecision {
	reasons := make([]string, 0, len(decision.Reasons))
	for _, reason := range decision.Reasons {
		if reason != emptyFinalTextReason {
			reasons = append(reasons, reason)
		}
	}
	decision.Reasons = reasons
	decision.Allowed = len(reasons) == 0
	return decision
}

func (d finalizationDecision) continuationPrompt() string {
	var builder strings.Builder
	builder.WriteString("【系统最终化检查未通过】\n")
	for _, reason := range d.Reasons {
		builder.WriteString("- ")
		builder.WriteString(reason)
		builder.WriteString("\n")
	}
	builder.WriteString(`
请继续完成缺失步骤，不要输出最终总结：
1. 先处理尚未返回结果的工具调用；
2. 对未确认的目标继续使用工具验证，并写回事实、资产和漏洞；
3. 目标已经被证据满足后，调用 project_update_goal(status="met")；
4. 目标确认不再适用时，调用 project_update_goal(status="abandoned")；
5. 对已执行的安全测试调用 project_record_test 记录 tested_clean/confirmed/blocked 结果；
6. blocked intent 必须派生替代意图，或明确标记为 exhausted；
7. 如果识别出下一步方向，先调用 project_add_intent 或 project_plan_hypotheses 写入，再立即执行；
8. 如果仍有未覆盖目标、可验证假设或高价值链式利用方向，直接继续执行最高价值方向，不要询问用户是否继续；
9. 完成全部必要步骤后再给出最终结论，不要重复已经完成的工作。`)
	return builder.String()
}

func finalizationIncompleteText(candidate string, decision finalizationDecision) string {
	notice := "【最终化检查未通过】\n"
	for _, reason := range decision.Reasons {
		notice += "- " + reason + "\n"
	}
	notice += "本轮已自动续跑，但仍未满足最终交付条件。请继续发送“继续”推进，或检查目标与证据状态。"
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return notice
	}
	return candidate + "\n\n---\n" + notice
}

func (s *Service) checkFinalization(
	ctx context.Context,
	conversationID string,
	projectID string,
	userID string,
	runStartedAt time.Time,
	capture *runCapture,
	finalText ...string,
) finalizationDecision {
	decision := finalizationDecision{Allowed: true}
	scope := s.missionScopeForConversation(ctx, conversationID)
	if execution, ok := missionExecutionFromContext(ctx); ok {
		scope = execution.Scope
		if execution.Plan.taskOnly() || execution.Phase == missionPhaseAsset {
			return checkTaskOnlyFinalization(
				s,
				ctx,
				conversationID,
				runStartedAt,
				&decision,
				capture,
				execution,
				finalText...,
			)
		}
	}
	if capture != nil {
		decision.PendingToolCalls = capture.pendingToolCalls()
		decision.HasExternalTools = capture.externalToolCalls > 0
	}

	if len(decision.PendingToolCalls) > 0 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(
			"存在尚未返回结果的工具调用：%s",
			strings.Join(decision.PendingToolCalls, ", "),
		))
	}
	if completed, findingID, reason := missionObjectiveCompletion(ctx); completed {
		decision.ObjectiveCompleted = true
		decision.ObjectiveReason = reason
		decision.Allowed = len(decision.PendingToolCalls) == 0
		if decision.Allowed && strings.TrimSpace(decision.ObjectiveReason) == "" {
			decision.ObjectiveReason = "明确目标已由漏洞 " + findingID + " 的利用证据满足"
		}
		return decision
	}

	var nodes []database.GraphNode
	if s.db != nil && strings.TrimSpace(projectID) != "" {
		if items, err := s.db.ListProjectGraphNodesByAsset(
			ctx,
			projectID,
			strings.TrimSpace(execctx.AssetID(ctx)),
		); err == nil {
			nodes = items
		} else {
			decision.Reasons = append(decision.Reasons, "无法读取项目目标和意图状态")
		}
	}

	openGoals := make([]database.GraphNode, 0)
	activeIntents := make([]database.GraphNode, 0)
	for _, node := range nodes {
		if !scope.IncludesNode(node) {
			continue
		}
		switch node.Kind {
		case "goal":
			if node.Status != "met" && node.Status != "abandoned" {
				openGoals = append(openGoals, node)
			}
		case "intent":
			if node.Status == "open" || node.Status == "running" {
				activeIntents = append(activeIntents, node)
			}
			if node.Status == "capacity_blocked" {
				decision.CapacityBlockedIntents++
			}
		}
	}
	decision.OpenGoalCount = len(openGoals)
	decision.ActiveIntentCount = len(activeIntents)

	if s.db != nil && strings.TrimSpace(projectID) != "" {
		edges, err := s.db.ListProjectGraphEdges(ctx, projectID)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法读取意图派生关系")
		} else {
			nodeByID := make(map[string]database.GraphNode, len(nodes))
			for _, node := range nodes {
				if !scope.IncludesNode(node) {
					continue
				}
				nodeByID[node.ID] = node
			}
			derivedSources := make(map[string]bool)
			for _, edge := range edges {
				if edge.Rel == "derived_from" {
					child, ok := nodeByID[edge.DstID]
					if ok &&
						child.Kind == "intent" &&
						(child.Status == "open" || child.Status == "running") {
						derivedSources[edge.SrcID] = true
					}
				}
			}
			for _, node := range nodes {
				if !scope.IncludesNode(node) {
					continue
				}
				if node.Kind == "intent" &&
					node.Status == "blocked" &&
					!derivedSources[node.ID] {
					decision.DerivableBlockedIntents++
				}
			}
		}
	}

	taskLike := decision.HasExternalTools ||
		len(activeIntents) > 0 ||
		decision.DerivableBlockedIntents > 0 ||
		decision.CapacityBlockedIntents > 0
	hasScopedAssetMetrics := !scope.Active || len(scope.AssetIDs) > 0
	if decision.HasExternalTools &&
		s.db != nil &&
		strings.TrimSpace(projectID) != "" &&
		hasScopedAssetMetrics {
		var metrics database.ProjectFinalizationMetrics
		var err error
		if scope.Active && len(scope.AssetIDs) > 0 {
			metrics, err = s.db.ProjectFinalizationMetricsForAssets(ctx, projectID, userID, scope.AssetIDs)
		} else {
			metrics, err = s.db.ProjectFinalizationMetrics(ctx, projectID, userID)
		}
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法确认项目最终化指标")
		} else {
			decision.AssetCount = metrics.AssetsTotal
			if metrics.AssetsTotal == 0 {
				decision.Reasons = append(decision.Reasons, "项目资产为空：本次任务执行了外部工具，但未登记任何资产")
			}
			decision.TestTotal = metrics.TestsTotal
			decision.TestCovered = metrics.TestsCovered
			decision.TestOpen = metrics.TestsOpenRequired
			decision.TestOpenOptional = metrics.TestsOpenOptional
			decision.TestSuspicious = metrics.TestsSuspicious
			if metrics.TestsTotal == 0 {
				decision.Reasons = append(decision.Reasons, "已执行外部工具但没有记录任何测试维度")
			}
			if metrics.TestsOpenRequired > 0 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf(
					"存在 %d 项必需测试未完成",
					metrics.TestsOpenRequired,
				))
			}
			if metrics.TestsSuspicious > 0 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf(
					"存在 %d 项可疑测试结果待验证",
					metrics.TestsSuspicious,
				))
			}
			if metrics.FindingsConfirmedWithoutEvidence > 0 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf(
					"存在 %d 条已确认漏洞缺少证据",
					metrics.FindingsConfirmedWithoutEvidence,
				))
			}
		}
	}
	if s.db != nil && strings.TrimSpace(projectID) != "" {
		conflicts, err := s.db.ListProjectFactConflicts(ctx, projectID, 200)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法确认事实冲突状态")
		} else {
			blocking := 0
			for _, conflict := range conflicts {
				if !scope.IncludesAsset(conflict.AssetID) &&
					!scope.IncludesText(conflict.Key+" "+projectFactSummary(conflict)) {
					continue
				}
				if conflict.Priority >= 70 ||
					conflict.MemoryKind == "scope" ||
					conflict.MemoryKind == "constraint" ||
					conflict.MemoryKind == "credential" {
					blocking++
				}
			}
			decision.UnresolvedConflicts = blocking
			if blocking > 0 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf(
					"存在 %d 项高优先级事实冲突未解决",
					blocking,
				))
			}
		}
	}
	if taskLike {
		for index, node := range activeIntents {
			if index >= 3 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("另有 %d 条未完成意图", len(activeIntents)-index))
				break
			}
			decision.Reasons = append(decision.Reasons, fmt.Sprintf(
				"存在未完成意图：[%s] %s",
				node.Status,
				truncateProjectText(node.Title, situationTextRune),
			))
		}
		for index, node := range openGoals {
			if index >= 3 {
				decision.Reasons = append(decision.Reasons, fmt.Sprintf("另有 %d 个未完成目标", len(openGoals)-index))
				break
			}
			decision.Reasons = append(decision.Reasons, fmt.Sprintf(
				"目标未完成：[%s] %s",
				node.Status,
				truncateProjectText(node.Title, situationTextRune),
			))
		}
	}
	if taskLike && decision.DerivableBlockedIntents > 0 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(
			"存在 %d 个 blocked 意图尚未派生替代路径或标记 exhausted",
			decision.DerivableBlockedIntents,
		))
	}
	if taskLike && decision.CapacityBlockedIntents > 0 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(
			"存在 %d 个 intent 因容量受限暂未派生替代路径，等待容量释放后恢复",
			decision.CapacityBlockedIntents,
		))
	}

	if decision.HasExternalTools && s.db != nil && strings.TrimSpace(conversationID) != "" {
		verified, err := s.db.HasCompletedToolExecutionSince(ctx, conversationID, runStartedAt)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法确认本次运行的执行证据")
		} else if verified {
			decision.EvidenceVerified = true
		} else {
			decision.Reasons = append(decision.Reasons, "证据不足：本次任务调用了外部工具，但没有成功完成的执行记录")
		}
	}

	if len(finalText) > 0 && looksLikeContinuationQuestion(finalText[0]) &&
		s.db != nil && strings.TrimSpace(projectID) != "" {
		if !execctx.AutoContinue(ctx) {
			decision.PendingUserConfirmation = true
			decision.PauseOnQuestion = true
		}
		coverage, err := s.db.ProjectCoverage(ctx, projectID, userID)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法确认是否仍有可执行方向")
		} else {
			actionable := make([]database.CoverageTarget, 0, len(coverage.NextTargets))
			for _, target := range coverage.NextTargets {
				if scope.IncludesAsset(target.RefID) || scope.IncludesText(target.Label) {
					actionable = append(actionable, target)
				}
			}
			decision.ActionableNextTargets = len(actionable)
			if decision.ActionableNextTargets > 0 ||
				decision.TestOpenOptional > 0 {
				decision.PendingUserConfirmation = true
				if execctx.AutoContinue(ctx) {
					decision.Reasons = append(
						decision.Reasons,
						"仍有可执行目标，禁止询问用户是否继续；请直接选择最高价值方向继续验证",
					)
				} else {
					decision.PauseOnQuestion = true
				}
			}
			coverage, coverageErr := s.db.ProjectCoverage(ctx, projectID, userID)
			if coverageErr != nil {
				decision.Reasons = append(decision.Reasons, "无法确认资产完整覆盖状态")
			} else {
				decision.AssetsCovered = coverage.AssetsCovered
				decision.AssetsPartial = coverage.AssetsPartial
				decision.AssetsUntested = coverage.AssetsUntested
				if scope.Active {
					decision.AssetsPartial = 0
					decision.AssetsUntested = 0
				}
				if coverage.AssetsPartial > 0 {
					decision.Reasons = append(decision.Reasons, fmt.Sprintf(
						"存在 %d 个资产已有观察但测试计划未完整覆盖",
						coverage.AssetsPartial,
					))
				}
				if coverage.AssetsUntested > 0 {
					decision.Reasons = append(decision.Reasons, fmt.Sprintf(
						"存在 %d 个资产尚未开始测试",
						coverage.AssetsUntested,
					))
				}
			}
		}
	}

	decision.Allowed = len(decision.Reasons) == 0
	return decision
}

func checkTaskOnlyFinalization(
	service *Service,
	ctx context.Context,
	conversationID string,
	runStartedAt time.Time,
	decision *finalizationDecision,
	capture *runCapture,
	execution missionExecution,
	finalText ...string,
) finalizationDecision {
	if decision == nil {
		decision = &finalizationDecision{Allowed: true}
	}
	if capture != nil {
		decision.PendingToolCalls = capture.pendingToolCalls()
		decision.HasExternalTools = capture.externalToolCalls > 0
	}
	if len(decision.PendingToolCalls) > 0 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(
			"存在尚未返回结果的工具调用：%s",
			strings.Join(decision.PendingToolCalls, ", "),
		))
	}
	if missionRequiresAssetTool(execution.Plan, execution.Phase) &&
		(capture == nil ||
			(!capture.hasProjectListResource("assets") &&
				!capture.hasToolCall("project_list_assets", "project_insert_assets"))) {
		decision.Reasons = append(decision.Reasons, "尚未实际读取或登记项目资产")
	}
	if execution.Plan.Mode == missionModeProjectWrite &&
		(capture == nil || !capture.hasToolCall(execution.Plan.WriteTools...)) {
		decision.Reasons = append(decision.Reasons, "尚未实际执行项目数据写操作")
	}
	if missionStageIsLocalAnalysis(execution.Plan, execution.Phase) &&
		(capture == nil ||
			(capture.externalToolCalls == 0 && capture.workerAgentCalls == 0)) {
		decision.Reasons = append(decision.Reasons, "尚未对指定源码或 App 包执行本地分析")
	}
	if execution.Plan.Mode == missionModeRetest &&
		(capture == nil || !capture.hasToolCall("project_retest_finding")) {
		decision.Reasons = append(decision.Reasons, "复测结果尚未写回漏洞记录")
	}
	if missionStageAllowsNetwork(execution.Phase) {
		if capture == nil || capture.externalToolCalls == 0 {
			decision.Reasons = append(decision.Reasons, "当前运行时阶段没有实际执行验证工具")
		} else if service != nil && service.db != nil {
			verified, err := service.db.HasCompletedToolExecutionSince(ctx, conversationID, runStartedAt)
			if err != nil {
				decision.Reasons = append(decision.Reasons, "无法确认运行时验证证据")
			} else if !verified {
				decision.Reasons = append(decision.Reasons, "运行时阶段没有成功完成的工具证据")
			} else {
				decision.EvidenceVerified = true
			}
		}
	}
	if missionRequiresAssetTool(execution.Plan, execution.Phase) &&
		len(finalText) > 0 &&
		looksLikeContinuationQuestion(finalText[0]) {
		if !execctx.AutoContinue(ctx) {
			decision.PendingUserConfirmation = true
			decision.PauseOnQuestion = true
		} else {
			decision.Reasons = append(decision.Reasons, "资产阶段尚未闭环：禁止向用户询问是否继续，请完成当前资产整理")
		}
	}
	decision.Allowed = len(decision.Reasons) == 0
	return *decision
}

func looksLikeContinuationQuestion(text string) bool {
	value := strings.ToLower(strings.TrimSpace(text))
	if value == "" {
		return false
	}
	for _, pattern := range []string{
		"是否继续",
		"需要我继续",
		"如需我继续",
		"要我继续",
		"要不要我",
		"是否要我",
		"需要继续吗",
		"继续别的",
		"继续其他",
		"下一步吗",
		"是否要",
		"要不要继续",
		"请确认是否",
		"如需继续",
		"如需进一步",
		"可继续验证",
	} {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}

type missionProgress struct {
	FactsTotal      int
	FindingsTotal   int
	TestsCovered    int
	AssetsTested    int
	AssetsCovered   int
	AssetsPartial   int
	AssetsBlocked   int
	AssetsUntested  int
	IntentsOpen     int
	IntentsRunning  int
	TestsSuspicious int
	EvidenceGaps    int
	NextTargets     int
}

func (s *Service) missionProgress(ctx context.Context, projectID, userID string) missionProgress {
	if s == nil || s.db == nil || strings.TrimSpace(projectID) == "" {
		return missionProgress{}
	}
	coverage, err := s.db.ProjectCoverage(ctx, projectID, userID)
	if err != nil || coverage == nil {
		return missionProgress{}
	}
	return missionProgress{
		FactsTotal:      coverage.FactsTotal,
		FindingsTotal:   coverage.FindingsTotal,
		TestsCovered:    coverage.TestsCovered,
		AssetsTested:    coverage.AssetsTested,
		AssetsCovered:   coverage.AssetsCovered,
		AssetsPartial:   coverage.AssetsPartial,
		AssetsBlocked:   coverage.AssetsBlocked,
		AssetsUntested:  coverage.AssetsUntested,
		IntentsOpen:     coverage.IntentsOpen,
		IntentsRunning:  coverage.IntentsRunning,
		TestsSuspicious: coverage.TestsSuspicious,
		EvidenceGaps:    coverage.FactsWithoutEvidence + coverage.FindingsWithoutEvidence,
		NextTargets:     len(coverage.NextTargets),
	}
}
