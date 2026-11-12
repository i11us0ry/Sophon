package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/observability"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"
)

// pentSubAgentPrompt 是 Sophon 渗透子 Agent 的配置提示词，
// 去掉了 Claude 运行时相关内容，仅保留渗透测试工程师的角色定义。
const pentSubAgentPrompt = `你是 Sophon 的 Deep Path 受限子 Agent，负责在一个明确任务范围内完成安全测试、漏洞分析、信息收集和证据验证。

核心职责：
1. 先理解当前任务、项目目标、授权范围和已有态势，再选择最小必要的工具执行。
2. 只处理分配给自己的任务或测试假设，不得扩展到无关资产、接口或历史项目。
3. 每个结论必须绑定工具输出、请求响应、文件位置或可复核证据，并区分已确认、待验证、技术阻断和策略阻断。
4. 未发现漏洞时写回 tested_clean 和负向证据；发现漏洞时先保存可复现证据，再完成当前任务，不伪造结果。
5. 不能在子 Agent 中继续派生新的子 Agent，执行深度固定为 1。

安全边界：
- 仅在用户明确授权和当前项目范围内测试。
- 涉及人工审批的工具必须遵循平台审批流程，不得绕过策略或拦截器。
- 不访问与任务无关的敏感路径，不批量导出真实个人信息，不使用发现的凭据扩大影响。
- 工具失败后先分析是否可修复；可修复问题修改参数或命令后重试，不可修复时说明原因并停止该方向。

输出要求：报告已完成动作、关键证据、发现、阻断项和下一步建议，结论清晰、简洁、可复现。`

const (
	pentToolExecute           = "pent_agent_execute"
	pentToolPlanHypotheses    = "pent_agent_plan_hypotheses"
	pentToolExecuteHypothesis = "pent_agent_execute_hypothesis"
	maxSubagentSkills         = 5
)

var subAgentToolNames = []string{
	pentToolExecute,
	pentToolPlanHypotheses,
	pentToolExecuteHypothesis,
}

// 合并前的旧工具名：不再暴露给模型，但保留调用提示，避免历史提示词或子 Agent 生成旧名时中断。
var subAgentLegacyToolHints = map[string]string{
	"pent_agent_run_pentest_task":      `请改用 pent_agent_execute：{"task":"<任务描述>","mode":"execute","mcp":"all|none|服务名/工具名"}`,
	"pent_agent_analyze_vulnerability": `请改用 pent_agent_execute：{"task":"<漏洞描述、PoC、影响范围>","mode":"analyze"}`,
	"pent_agent_diagnose":              `请改用 pent_agent_execute：{"task":"<目标 URL / IP / 域名>","mode":"diagnose"}`,
	"pent_agent_status":                `该工具已下线：子 Agent 执行结果会直接回传到当前对话，不再单独查询状态`,
}

type subAgentRunner struct {
	service *Service

	mu        sync.Mutex
	sem       chan struct{}
	running   bool
	count     int
	lastTask  string
	lastReply string
}

type runSubagentBudgetKey struct{}

type runSubagentBudget struct {
	mu    sync.Mutex
	limit int
	count int
}

func withRunSubagentBudget(ctx context.Context, limit int) context.Context {
	if limit <= 0 {
		return ctx
	}
	return context.WithValue(ctx, runSubagentBudgetKey{}, &runSubagentBudget{limit: limit})
}

func reserveRunSubagent(ctx context.Context) error {
	budget, _ := ctx.Value(runSubagentBudgetKey{}).(*runSubagentBudget)
	if budget == nil {
		return nil
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.count >= budget.limit {
		return fmt.Errorf("本轮子 Agent 数量预算已耗尽（%d/%d）", budget.count, budget.limit)
	}
	budget.count++
	return nil
}

func newSubAgentRunner(service *Service) *subAgentRunner {
	limit := service.configSnapshot().AgentSubagentConcurrency
	if limit <= 0 {
		limit = 2
	}
	return &subAgentRunner{service: service, sem: make(chan struct{}, limit)}
}

// run 在进程内启动一个复用主模型与工具集的子 Agent，返回最终文本。
// 子 Agent 只会拿到 baseTools，不包含这 5 个入口工具，避免递归调用。
// instruction 组装子 Agent 系统提示：渗透角色 + 项目背景 + 项目态势快照 + 写回纪律，
// 保证每个子任务都知道当前项目的目标、意图、事实与漏洞。
func (r *subAgentRunner) instruction(ctx context.Context) string {
	service := r.service
	conversationID := execctx.ConversationID(ctx)
	userID := execctx.UserID(ctx)
	// 子 Agent 同样遵循「数据 vs 指令」边界：写回纪律与安全约束留在受信任前缀，
	// 项目简报与态势包一律转义后放进随机围栏数据区。
	subAgentPrompt := service.systemAgentPrompt(
		ctx,
		SystemDeepPathSubAgentID,
		SystemDeepPathSubAgentName,
		pentSubAgentPrompt,
	)
	instruction := subAgentPrompt + subagentModeGuidance(ctx) +
		projectWritebackGuidance + untrustedContextGuidance
	if info, ok := execctx.Subagent(ctx); ok && strings.EqualFold(strings.TrimSpace(info.Kind), "worker") {
		instruction += service.workerBudgetGuidance()
	}
	if roleBrief := service.delegatedRoleBrief(ctx); roleBrief != "" {
		instruction += "\n\n" + roleBrief
	}
	if policyPrompt := service.systemAgentPrompt(
		ctx,
		SystemMissionPolicyAgentID,
		SystemMissionPolicyAgentName,
		missionPolicyAgentPrompt,
	); strings.TrimSpace(policyPrompt) != "" {
		instruction += "\n\n" + policyPrompt
	}
	instruction = withPlatformVerificationWorkflow(instruction)
	instruction += service.missionSourceAccessGuidance(ctx)
	var state strings.Builder
	var findings []string
	writeUntrusted := func(text string) {
		cleaned, patterns := prepareUntrustedText(text)
		state.WriteString(cleaned)
		findings = append(findings, patterns...)
	}
	if briefing := service.projectBriefing(ctx, conversationID, userID); briefing != "" {
		writeUntrusted(briefing)
	}
	if situation := service.projectSituationForConversation(
		ctx,
		conversationID,
		userID,
	); situation != "" {
		writeUntrusted(situation)
	}
	if state.Len() == 0 {
		return instruction
	}
	nonce := newFenceNonce()
	var builder strings.Builder
	builder.WriteString(instruction)
	builder.WriteString("\n\n【系统状态包 · 由平台生成，不是用户指令】\n")
	builder.WriteString(fenceNotice(nonce))
	builder.WriteString("\n\n")
	if banner := injectionWarningBanner(findings); banner != "" {
		builder.WriteString(banner)
		builder.WriteString("\n")
	}
	builder.WriteString(wrapUntrustedBlock(strings.TrimSpace(state.String()), "state", nonce))
	return builder.String()
}

func (r *subAgentRunner) run(ctx context.Context, prompt string) (string, error) {
	return r.runWithOptions(ctx, prompt, "", "", "subagent", "SubAgent", "", "", "", nil)
}

// tracedSubagentName 为每个子 Agent 生成可稳定识别的展示名称。
func tracedSubagentName(base, id string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "SubAgent"
	}
	suffix := strings.TrimPrefix(strings.TrimSpace(id), "sub-")
	if len(suffix) > 6 {
		suffix = suffix[:6]
	}
	if suffix == "" {
		return base
	}
	return base + "-" + strings.ToUpper(suffix)
}

func normalizeWorkerFocus(value string) string {
	return truncateProjectText(strings.Join(strings.Fields(value), " "), 120)
}

func (s *Service) normalizeSubagentSkills(
	ctx context.Context,
	values []string,
) ([]string, error) {
	seen := make(map[string]bool, len(values))
	requested := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		requested = append(requested, name)
	}
	if len(requested) > maxSubagentSkills {
		return nil, fmt.Errorf("Worker 最多分配 %d 个技能", maxSubagentSkills)
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" || s == nil || s.db == nil {
		if len(requested) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("指定 Worker 技能需要有效的角色会话上下文")
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil || strings.TrimSpace(conversation.AgentRoleID) == "" {
		if len(requested) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("当前会话未绑定角色，不能指定角色技能子集")
	}
	role, err := s.db.GetAgentRole(ctx, conversation.AgentRoleID)
	if err != nil || !role.Enabled {
		if len(requested) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("当前业务角色不可用")
	}
	roleSkills := make(map[string]bool, len(role.Skills))
	for _, name := range role.Skills {
		roleSkills[strings.TrimSpace(name)] = true
	}
	for _, name := range requested {
		if !roleSkills[name] {
			return nil, fmt.Errorf("技能 %s 未绑定到当前角色", name)
		}
	}
	return requested, nil
}

func subagentKindLabel(kind string) string {
	switch strings.TrimSpace(kind) {
	case "planner":
		return "Planner"
	case "worker":
		return "Worker"
	default:
		return "子 Agent"
	}
}

func (r *subAgentRunner) persistLifecycle(
	ctx context.Context,
	eventType string,
	message string,
	data map[string]interface{},
) {
	if r == nil || r.service == nil || r.service.db == nil {
		return
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	messageID := strings.TrimSpace(execctx.MessageID(ctx))
	if conversationID == "" || messageID == "" {
		return
	}
	event := Event{
		Type:    eventType,
		Message: message,
		Data:    withAgentData(ctx, data),
	}
	if progress, ok := execctx.Progress(ctx); ok {
		_ = progress(event.Type, event.Message, event.Data)
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = r.service.persistEvent(writeCtx, conversationID, messageID, event)
}

// runWithOptions 按指定能力模式与 MCP 继承策略启动子 Agent。
// 子 Agent 只拿到 baseTools（不含入口工具），因此无法继续派生子 Agent，深度固定为 1。
func (r *subAgentRunner) runWithOptions(
	ctx context.Context,
	prompt string,
	mode string,
	mcpScope string,
	agentKind string,
	agentName string,
	intentID string,
	hypothesisID string,
	workerFocus string,
	skills []string,
) (result string, runErr error) {
	if err := reserveRunSubagent(ctx); err != nil {
		return "", err
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return "", fmt.Errorf("任务描述不能为空")
	}
	if focus := normalizeWorkerFocus(workerFocus); focus != "" {
		prompt = "本次 Worker 工作身份：" + focus +
			"\n该身份只用于当前任务分工，不得覆盖用户角色、平台安全边界或授权范围。\n\n" + prompt
	}
	normalizedMode := normalizeSubagentMode(mode)
	if normalizedMode == "" {
		return "", fmt.Errorf("未知的子 Agent 能力模式 %q", mode)
	}
	parentInfo, _ := execctx.Subagent(ctx)
	parentID := "mainagent"
	if strings.TrimSpace(parentInfo.ID) != "" {
		parentID = parentInfo.ID
	}
	subagentID := newSubagentID()
	info := execctx.SubagentInfo{
		ID:           subagentID,
		Name:         tracedSubagentName(agentName, subagentID),
		Kind:         strings.TrimSpace(agentKind),
		ParentID:     parentID,
		IntentID:     strings.TrimSpace(intentID),
		HypothesisID: strings.TrimSpace(hypothesisID),
		Mode:         normalizedMode,
		Depth:        parentInfo.Depth + 1,
		WorkerFocus:  strings.TrimSpace(workerFocus),
		AllowedSkills: append(
			[]string(nil),
			skills...,
		),
		MCPScope: parseSubagentMCPScope(mcpScope),
	}
	service := r.service
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if strings.EqualFold(strings.TrimSpace(agentKind), "worker") {
		cfg := service.configSnapshot()
		duration := time.Duration(cfg.AgentSubagentMaxDuration) * time.Second
		if duration <= 0 {
			duration = 30 * time.Minute
		}
		workerCtx, workerCancel := context.WithTimeout(ctx, duration)
		defer workerCancel()
		ctx = workerCtx
		info.CPUSeconds = cfg.AgentSubagentMaxCPUSeconds
		info.MaxProcesses = cfg.AgentSubagentMaxProcesses
		ctx = withWorkerBudget(ctx, cfg, workerCancel)
	}
	ctx = execctx.WithSubagent(ctx, info)
	defer func() {
		if strings.TrimSpace(hypothesisID) == "" || service == nil || service.db == nil {
			return
		}
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = service.db.ResetProjectHypothesisIfRunning(
			writeCtx,
			hypothesisID,
			"Worker 未写回最终状态，已释放为待重试",
		)
	}()

	r.mu.Lock()
	r.running = true
	r.count++
	r.lastTask = prompt
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()
	service.emit(agentEvent(ctx, observability.TypeSubagentStarted))
	startedAt := time.Now()
	defer func() {
		event := agentEvent(ctx, observability.TypeSubagentCompleted)
		event.DurationMS = time.Since(startedAt).Milliseconds()
		lifecycleData := map[string]interface{}{
			"durationMs": event.DurationMS,
			"task":       truncateProjectText(prompt, 2000),
		}
		if runErr != nil {
			event.EventType = observability.TypeSubagentFailed
			event.Success = observability.Bool(false)
			event.ErrorCategory = observability.ErrorCategory(runErr.Error())
			event.Detail = truncateEventDetail(runErr.Error())
			lifecycleData["status"] = "failed"
			lifecycleData["error"] = truncateProjectText(runErr.Error(), 2000)
		} else {
			event.Success = observability.Bool(true)
			lifecycleData["status"] = "completed"
			if result = strings.TrimSpace(result); result != "" {
				lifecycleData["result"] = truncateProjectText(result, 2000)
			}
		}
		service.emit(event)
		label := subagentKindLabel(agentKind)
		lifecycleMessage := label + " 已完成"
		if runErr != nil {
			lifecycleMessage = label + " 执行失败"
		}
		r.persistLifecycle(ctx, event.EventType, lifecycleMessage, lifecycleData)
	}()
	r.persistLifecycle(
		ctx,
		observability.TypeSubagentStarted,
		subagentKindLabel(agentKind)+" 已启动",
		map[string]interface{}{
			"task": truncateProjectText(prompt, 2000),
		},
	)

	maxIterations := service.configSnapshot().AgentMaxIterations
	if maxIterations <= 0 {
		maxIterations = service.maxIterations
	}
	instruction := r.instruction(ctx)
	chatAgent, err := adk.NewChatModelAgent(ctx, &adk.ChatModelAgentConfig{
		Name:          "pent-sub-agent",
		Instruction:   instruction,
		Model:         service.model,
		MaxIterations: maxIterations,
		ToolsConfig: adk.ToolsConfig{
			ToolsNodeConfig: compose.ToolsNodeConfig{
				Tools:               wrapWorkerBudgetTools(ctx, service.subAgentActiveTools(ctx)),
				UnknownToolsHandler: service.unknownToolHandler,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("创建渗透子 Agent 失败: %w", err)
	}

	runner := adk.NewRunner(ctx, adk.RunnerConfig{
		Agent:           chatAgent,
		EnableStreaming: true,
	})
	messages := []*schema.Message{schema.UserMessage(prompt)}
	usage := newUsageTracker(
		service.db,
		execctx.ConversationID(ctx),
		execctx.UserID(ctx),
		execctx.MessageID(ctx),
		messages,
		"subagent",
		service.configSnapshot().LLMModel,
	)
	usage.budget = runTokenBudgetFromContext(ctx)
	iter := runner.Run(ctx, messages)
	emitProgress := func(event Event) error {
		if progress, ok := execctx.Progress(ctx); ok {
			return progress(event.Type, event.Message, event.Data)
		}
		return nil
	}

	var capture runCapture
	for {
		event, ok := iter.Next()
		if !ok {
			break
		}
		if event.Err != nil {
			if runTokenBudgetFromContext(ctx).exceeded() {
				return capture.finalText(), errRunTokenBudgetExhausted
			}
			if isMaxIterationsError(event.Err) {
				final := maxIterationsResult(&capture, maxIterations)
				r.mu.Lock()
				r.lastReply = final
				r.mu.Unlock()
				return final, nil
			}
			return capture.finalText(), event.Err
		}
		if event.Output == nil || event.Output.MessageOutput == nil {
			continue
		}
		if err := service.consumeMessage(
			ctx,
			usage,
			event.Output.MessageOutput,
			&capture,
			emitProgress,
		); err != nil {
			if runTokenBudgetFromContext(ctx).exceeded() {
				return capture.finalText(), errRunTokenBudgetExhausted
			}
			return capture.finalText(), err
		}
	}

	final := capture.finalText()
	if final == "" {
		final = "子 Agent 未返回文本结果。"
	}
	r.mu.Lock()
	r.lastReply = final
	r.mu.Unlock()
	return final, nil
}

func (r *subAgentRunner) status() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	state := "空闲"
	if r.running {
		state = "执行中"
	}
	summary := "-"
	if r.lastReply != "" {
		runes := []rune(r.lastReply)
		if len(runes) > 200 {
			summary = string(runes[:200]) + "..."
		} else {
			summary = r.lastReply
		}
	}
	task := r.lastTask
	if task == "" {
		task = "-"
	}
	return fmt.Sprintf(
		"运行状态: %s\n任务执行次数: %d\n最近任务: %s\n最近结果摘要: %s\n模型: %s",
		state,
		r.count,
		task,
		summary,
		r.modelName(),
	)
}

func (r *subAgentRunner) modelName() string {
	snapshot := r.service.configSnapshot()
	if snapshot.AgentMock || strings.TrimSpace(snapshot.LLMAPIKey) == "" {
		return "mock"
	}
	if strings.TrimSpace(snapshot.LLMModel) == "" {
		return "默认模型"
	}
	return snapshot.LLMModel
}

// newSubAgentTools 构造 3 个与 Sophon 子 Agent 能力对齐的原生工具：
// 统一执行入口（含 analyze/diagnose/plan 模式）、假设规划、假设执行。
func newSubAgentTools(service *Service) []tool.BaseTool {
	runner := newSubAgentRunner(service)
	return []tool.BaseTool{
		&jsonTool{
			name: pentToolExecute,
			desc: "调用渗透子 Agent 执行任务。mode 决定能力模式：" +
				"execute（默认，通用渗透测试任务）、analyze（只读分析漏洞信息并给出修复建议）、" +
				"diagnose（对目标做无破坏性安全诊断）。子 Agent 使用受限工具集执行并返回结果，" +
				"支持端口扫描、漏洞探测、Web 安全测试、信息收集等。",
			params: map[string]*schema.ParameterInfo{
				"task":         stringParam("任务描述；mode=analyze 时填漏洞描述/PoC/影响范围，mode=diagnose 时填目标 URL/IP/域名", true),
				"mode":         stringParam("能力模式：execute（默认）| analyze | diagnose | " + subagentModeHelp),
				"mcp":          stringParam("MCP 工具继承策略：all（默认）| none | 服务名/工具名/server__tool 列表"),
				"worker_focus": stringParam("本次 Worker 工作身份，例如“文件上传与路径审计”；不替代用户角色"),
				"skills":       stringArrayParam("可选：选择 1-3 个角色技能作为 Worker 的启发式参考；不是执行前置门禁"),
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Task        string   `json:"task"`
					Mode        string   `json:"mode"`
					MCP         string   `json:"mcp"`
					WorkerFocus string   `json:"worker_focus"`
					Skills      []string `json:"skills"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				if strings.TrimSpace(request.Task) == "" {
					return "", fmt.Errorf("task 不能为空")
				}
				skills, err := service.normalizeSubagentSkills(ctx, request.Skills)
				if err != nil {
					return "", err
				}
				task := strings.TrimSpace(request.Task)
				focus := normalizeWorkerFocus(request.WorkerFocus)
				agentName := "SubAgent"
				agentKind := "subagent"
				if focus != "" {
					agentName = focus
					agentKind = "worker"
				}
				switch strings.ToLower(strings.TrimSpace(request.Mode)) {
				case "analyze", "analysis":
					return runner.runWithOptions(ctx, fmt.Sprintf(
						"请对以下漏洞信息进行专业分析，包括：风险等级、影响范围、利用方式、修复建议。\n\n%s",
						task,
					), subagentModeReadOnly, request.MCP, agentKind, agentName, "", "", focus, skills)
				case "diagnose", "diagnosis":
					return runner.runWithOptions(ctx, fmt.Sprintf(
						"请对以下目标进行安全诊断和初步评估：%s\n\n包括：可达性、开放服务、常见漏洞面等。",
						task,
					), subagentModeExecute, request.MCP, agentKind, agentName, "", "", focus, skills)
				default:
					return runner.runWithOptions(
						ctx,
						task,
						request.Mode,
						request.MCP,
						agentKind,
						agentName,
						"",
						"",
						focus,
						skills,
					)
				}
			},
		},
		&singleStringTool{
			name:      pentToolPlanHypotheses,
			desc:      "以 Planner 身份分析项目资产和已有事实，规划结构化测试假设，不直接执行漏洞利用。",
			param:     "planning_task",
			paramDesc: "本轮规划目标、限制和重点关注方向",
			run: func(ctx context.Context, value string) (string, error) {
				plannerPrompt := service.systemAgentPrompt(
					ctx,
					SystemDeepPathPlannerID,
					SystemDeepPathPlannerName,
					deepPathPlannerAgentPrompt,
				)
				return runner.runWithOptions(
					ctx,
					plannerPrompt+"\n\n"+value,
					subagentModeReadWrite,
					"",
					"planner",
					"Planner",
					"",
					"",
					"",
					nil,
				)
			},
		},
		&jsonTool{
			name: pentToolExecuteHypothesis,
			desc: "以 Worker 身份领取一个测试假设，独立执行并写回结果或漏洞证据。",
			params: map[string]*schema.ParameterInfo{
				"hypothesis_id": stringParam("测试假设 id", true),
				"worker_focus":  stringParam("本次 Worker 工作身份，例如“SQL 注入与鉴权审计”"),
				"skills":        stringArrayParam("可选：选择 1-3 个角色技能作为 Worker 的启发式参考；不是执行前置门禁"),
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					HypothesisID string   `json:"hypothesis_id"`
					WorkerFocus  string   `json:"worker_focus"`
					Skills       []string `json:"skills"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				skills, err := service.normalizeSubagentSkills(ctx, request.Skills)
				if err != nil {
					return "", err
				}
				_, _, projectID, err := service.currentProject(ctx)
				if err != nil {
					return "", err
				}
				hypothesis, err := service.db.GetProjectTestResultByID(ctx, projectID, request.HypothesisID)
				if err != nil {
					return "", fmt.Errorf("测试假设不存在: %w", err)
				}
				if _, ok := database.NormalizeProjectTestResultStatus(hypothesis.Status); !ok {
					return "", fmt.Errorf("测试假设状态不合法")
				}
				if database.IsProjectTestResultTerminal(hypothesis.Status) {
					return "", fmt.Errorf("测试假设已经结束，不能重复执行")
				}
				workerPrompt := service.systemAgentPrompt(
					ctx,
					SystemDeepPathWorkerID,
					SystemDeepPathWorkerName,
					deepPathWorkerAgentPrompt,
				)
				prompt := fmt.Sprintf(
					"%s\n\n假设 id：%s\n资产 id：%s\n测试维度：%s\n测试技术：%s\n规划依据：%s\n预期证据：%s\n优先级：%d",
					workerPrompt,
					hypothesis.ID,
					hypothesis.AssetID,
					hypothesis.Dimension,
					orDefaultProjectToolValue(hypothesis.Technique, "-"),
					orDefaultProjectToolValue(hypothesis.Rationale, "-"),
					orDefaultProjectToolValue(hypothesis.Expected, "-"),
					hypothesis.Priority,
				)
				focus := normalizeWorkerFocus(request.WorkerFocus)
				agentName := "Worker"
				if focus != "" {
					agentName = focus
				}
				return runner.runWithOptions(
					ctx,
					prompt,
					subagentModeExecute,
					"",
					"worker",
					agentName,
					hypothesis.IntentID,
					request.HypothesisID,
					focus,
					skills,
				)
			},
		},
	}
}

type singleStringTool struct {
	name      string
	desc      string
	param     string
	paramDesc string
	run       func(context.Context, string) (string, error)
}

func (t *singleStringTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{
		Name: t.name,
		Desc: t.desc,
		ParamsOneOf: schema.NewParamsOneOfByParams(map[string]*schema.ParameterInfo{
			t.param: {
				Type:     schema.String,
				Desc:     t.paramDesc,
				Required: true,
			},
		}),
	}, nil
}

func (t *singleStringTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	_ ...tool.Option,
) (string, error) {
	args := map[string]string{}
	if strings.TrimSpace(argumentsInJSON) != "" && argumentsInJSON != "null" {
		if err := json.Unmarshal([]byte(argumentsInJSON), &args); err != nil {
			return "", fmt.Errorf("解析 %s 参数失败: %w", t.name, err)
		}
	}
	value := strings.TrimSpace(args[t.param])
	if value == "" {
		return "", fmt.Errorf("%s 不能为空", t.param)
	}
	return t.run(ctx, value)
}
