package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sophon/internal/execctx"
)

const (
	strategySwitchInterval      = 3
	emptyFinalTextReason        = "最终回答为空：模型只返回了推理或工具调用，尚未生成可交付结论"
	finalizationSynthesisPrompt = `【强制总结轮】工具执行阶段已结束，本轮禁止调用任何工具。
请基于当前会话、项目事实、测试结果、漏洞和已有工具输出，直接生成面向用户的最终文本。
说明已完成的工作、真实证据、实际影响、未验证项和外部阻塞。
不得把内部预算、工具次数或未执行步骤写成目标安全或漏洞不存在的证据；不得编造未实际执行的结果。
内部工具失败必须保留原始错误和可修复方式，不得把输入格式、路径、资源限制或工具实现错误写成“依赖缺失”。
不得只输出推理过程、工具计划或空内容。`

	iterationBudgetSynthesisPrompt = `【预算耗尽强制总结轮】Agent 迭代预算已耗尽，本轮禁止调用任何工具，也不得要求用户回复“继续”。
请立即基于当前会话、项目事实、测试结果、漏洞和已有工具输出生成最终可交付总结，必须包含：
1. 已完成的工作和已验证结论；
2. 关键证据、漏洞及实际影响；
3. 未完成项、未验证假设和真实阻塞原因；
4. 当前成果对应的下一步人工建议。
内部工具失败必须保留原始错误和可修复方式，不得把输入格式、路径、资源限制或工具实现错误写成“依赖缺失”，也不得据此挂起整个审计方向。
不得把内部迭代窗口、预算或工具次数当成漏洞不存在、任务证伪或目标安全的证据；不得编造任何未实际执行的结果。`

	tokenBudgetSynthesisPrompt = `【Token 预算收尾强制总结轮】单轮 Token 预算已接近或达到上限，本轮禁止调用任何工具，也不得要求用户回复“继续”。
请立即基于当前会话、项目事实、测试结果、漏洞和已有工具输出生成最终可交付总结，必须包含：
1. 已完成的工作和已验证结论；
2. 关键证据、漏洞及实际影响；
3. 未完成项、未验证假设和真实阻塞原因；
4. 当前成果对应的下一步人工建议。
内部工具失败必须保留原始错误和可修复方式，不得把输入格式、路径、资源限制或工具实现错误写成“依赖缺失”，也不得据此挂起整个审计方向。
不得把 Token 预算当成漏洞不存在、任务证伪或目标安全的证据；不得编造任何未实际执行的结果。`
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
	builder.WriteString("【系统检查】\n")
	for _, reason := range d.Reasons {
		builder.WriteString("- ")
		builder.WriteString(reason)
		builder.WriteString("\n")
	}
	builder.WriteString("请先处理这些具体问题，再给出最终答复。不要重复已经完成的工作；没有必须继续的检查项时直接结束。")
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
	if execution, ok := missionExecutionFromContext(ctx); ok {
		if execution.Plan.Mode == missionModeRetest ||
			strings.TrimSpace(execctx.CampaignID(ctx)) != "" {
			return checkTaskOnlyFinalization(
				s,
				ctx,
				conversationID,
				projectID,
				userID,
				runStartedAt,
				&decision,
				capture,
				execution,
				finalText...,
			)
		}
	}

	decision.Allowed = len(decision.Reasons) == 0
	return decision
}

func checkTaskOnlyFinalization(
	service *Service,
	ctx context.Context,
	conversationID string,
	projectID string,
	userID string,
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
	backgroundActive := false
	if service != nil {
		if handle := service.orchestrationFor(conversationID); handle != nil {
			status, _ := handle.snapshot()["status"].(string)
			backgroundActive = status == "running" || status == "paused"
		}
	}
	if len(decision.PendingToolCalls) > 0 {
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(
			"存在尚未返回结果的工具调用：%s",
			strings.Join(decision.PendingToolCalls, ", "),
		))
	}
	if execution.Plan.Mode == missionModeRetest {
		if completed, findingID, reason := missionObjectiveCompletion(ctx); completed {
			decision.ObjectiveCompleted = true
			decision.ObjectiveReason = reason
			decision.Allowed = len(decision.PendingToolCalls) == 0
			if decision.Allowed && strings.TrimSpace(decision.ObjectiveReason) == "" {
				decision.ObjectiveReason = "漏洞 " + findingID + " 的复测终态已写回"
			}
			return *decision
		}
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
	if !backgroundActive && missionStageIsLocalAnalysis(execution.Plan, execution.Phase) &&
		(capture == nil ||
			(capture.externalToolCalls == 0 && capture.workerAgentCalls == 0)) {
		decision.Reasons = append(decision.Reasons, "尚未对指定源码或 App 包执行本地分析")
	}
	if execution.Plan.Mode == missionModeRetest &&
		(capture == nil || !capture.hasToolCall("project_retest_finding")) {
		decision.Reasons = append(decision.Reasons, "复测结果尚未写回漏洞记录")
	}
	if execution.Plan.Coordinated && !backgroundActive {
		plannerReady, workersCompleted := coordinatedStateFromContext(ctx).snapshot()
		if !plannerReady {
			decision.Reasons = append(decision.Reasons, "强制多 Agent 编排尚未完成 Planner 前置规划")
		}
		if workersCompleted == 0 {
			decision.Reasons = append(decision.Reasons, "强制多 Agent 编排尚无成功写回终态的 Worker")
		}
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
	if decision.HasExternalTools && service != nil && service.db != nil &&
		strings.TrimSpace(projectID) != "" {
		hasAuditScope, changed, err := service.db.ProjectAuditStateSince(
			ctx,
			projectID,
			runStartedAt,
		)
		if err != nil {
			decision.Reasons = append(decision.Reasons, "无法确认本次运行是否产生项目进展")
		} else if hasAuditScope && !changed {
			decision.Reasons = append(decision.Reasons, fmt.Sprintf(
				"本次代码审计执行了 %d 次外部工具调用，但没有新增项目事实、审计单元、测试结果或漏洞；必须继续分析并把有效结论写回项目",
				decisionToolCallCount(capture),
			))
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

func decisionToolCallCount(capture *runCapture) int {
	if capture == nil {
		return 0
	}
	return capture.toolCallCount
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
