package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/observability"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

func newSubAgentTestService(t *testing.T) *Service {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	service, err := NewService(db, config.Config{AgentMock: true, AgentMaxIterations: 4}, nil, nil)
	if err != nil {
		t.Fatalf("创建 Agent 服务失败: %v", err)
	}
	return service
}

func findSubAgentTool(t *testing.T, tools []tool.BaseTool, name string) tool.InvokableTool {
	t.Helper()
	for _, item := range tools {
		info, err := item.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		if info.Name == name {
			invokable, ok := item.(tool.InvokableTool)
			if !ok {
				t.Fatalf("工具 %s 不可调用", name)
			}
			return invokable
		}
	}
	t.Fatalf("未找到工具 %s", name)
	return nil
}

func TestSubAgentToolsRegisteredWithoutRecursion(t *testing.T) {
	service := newSubAgentTestService(t)

	registered := map[string]bool{}
	for _, item := range service.tools {
		info, err := item.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		registered[info.Name] = true
	}
	for _, name := range subAgentToolNames {
		if !registered[name] {
			t.Fatalf("主工具集缺少 %s", name)
		}
	}

	for _, item := range service.baseTools {
		info, err := item.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		for _, name := range subAgentToolNames {
			if info.Name == name {
				t.Fatalf("子 Agent 工具 %s 不应出现在 baseTools 中", name)
			}
		}
	}
}

func TestAgentModeFiltersSubAgentTools(t *testing.T) {
	service := newSubAgentTestService(t)
	ctx := context.Background()

	fastNames := map[string]bool{}
	for _, item := range service.activeToolsForMode(ctx, agentModeFast) {
		info, err := item.Info(ctx)
		if err == nil && info != nil {
			fastNames[info.Name] = true
		}
	}
	for _, name := range subAgentToolNames {
		if fastNames[name] {
			t.Fatalf("Fast Path 不应暴露子 Agent 工具 %s", name)
		}
	}

	deepNames := map[string]bool{}
	for _, item := range service.activeToolsForMode(ctx, agentModeDeep) {
		info, err := item.Info(ctx)
		if err == nil && info != nil {
			deepNames[info.Name] = true
		}
	}
	for _, name := range subAgentToolNames {
		if !deepNames[name] {
			t.Fatalf("Deep Path 缺少子 Agent 工具 %s", name)
		}
	}
}

func TestWorkerAssignmentCombinesRoleFocusAndSkillSubset(t *testing.T) {
	service := newSubAgentTestService(t)
	skillsDir := filepath.Join(t.TempDir(), "skills")
	for _, item := range []struct {
		name        string
		description string
	}{
		{name: "skill-one", description: "技能一说明"},
		{name: "skill-two", description: "技能二说明"},
	} {
		dir := filepath.Join(skillsDir, item.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("创建技能目录失败: %v", err)
		}
		content := "---\nname: " + item.name + "\ndescription: " + item.description + "\n---\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o644); err != nil {
			t.Fatalf("写入技能失败: %v", err)
		}
	}
	service.cfg = config.Config{
		AgentMock:          true,
		AgentMaxIterations: 4,
		SkillsDir:          skillsDir,
	}
	now := time.Now().UTC()
	rolePrompt := "你是 NET 代码审计角色，只允许静态分析。"
	if err := service.db.UpsertAgentRole(t.Context(), database.AgentRole{
		ID: "role-worker-fusion", Name: "NET代码审计", Description: "NET 审计",
		Prompt: rolePrompt, DefaultMode: "auto",
		Skills: []string{"skill-one", "skill-two"}, Builtin: true, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	if err := service.db.CreateConversation(t.Context(), database.Conversation{
		ID: "conv-worker-fusion", OwnerUserID: "user-1", Title: "测试",
		AgentRoleID: "role-worker-fusion", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	ctx := execctx.WithConversationID(t.Context(), "conv-worker-fusion")
	ctx = execctx.WithUserID(ctx, "user-1")
	skills, err := service.normalizeSubagentSkills(ctx, []string{"skill-one", "skill-one"})
	if err != nil || len(skills) != 1 || skills[0] != "skill-one" {
		t.Fatalf("Worker 技能归一化失败: %#v err=%v", skills, err)
	}
	withPrimary, err := service.normalizeSubagentSkills(ctx, []string{"skill-two"})
	if err != nil || len(withPrimary) != 1 || withPrimary[0] != "skill-two" {
		t.Fatalf("角色主技能不应被强制加入 Worker 技能集: %#v err=%v", withPrimary, err)
	}
	if _, err := service.normalizeSubagentSkills(ctx, []string{"unbound-skill"}); err == nil {
		t.Fatalf("应拒绝分配角色外技能")
	}

	workerCtx := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-fusion", Name: "路由鉴权 Worker", Kind: "worker",
		Mode: subagentModeReadOnly, Depth: 1,
		WorkerFocus: "路由鉴权审计", AllowedSkills: skills,
	})
	instruction := newSubAgentRunner(service).instruction(workerCtx)
	for _, want := range []string{rolePrompt, "本次 Worker 可用技能：skill-one", "技能一说明"} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("Worker 指令缺少 %q: %s", want, instruction)
		}
	}
	if strings.Contains(instruction, "技能二说明") {
		t.Fatalf("Worker 指令不应包含未分配技能: %s", instruction)
	}
	agentData := withAgentData(workerCtx, nil)
	if traceString(agentData["workerFocus"]) != "路由鉴权审计" {
		t.Fatalf("Worker 事件缺少工作身份: %+v", agentData)
	}
	allowedSkills, _ := agentData["allowedSkills"].([]string)
	if len(allowedSkills) != 1 || allowedSkills[0] != "skill-one" {
		t.Fatalf("Worker 事件缺少技能子集: %+v", agentData)
	}

	execute := findSubAgentTool(t, service.tools, pentToolExecute)
	output, err := execute.InvokableRun(workerCtx, `{
		"task":"审计路由鉴权",
		"worker_focus":"路由鉴权审计",
		"skills":["skill-one"],
		"mode":"read_only"
	}`)
	if err != nil || !strings.Contains(output, "路由鉴权审计") || !strings.Contains(output, "审计路由鉴权") {
		t.Fatalf("Worker 分配执行失败: output=%q err=%v", output, err)
	}
}

func TestSubagentLifecycleIsPersisted(t *testing.T) {
	service := newSubAgentTestService(t)
	now := time.Now().UTC()
	if err := service.db.CreateConversation(t.Context(), database.Conversation{
		ID: "conv-worker-trace", OwnerUserID: "user-1", Title: "Worker 追踪",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	ctx := execctx.WithConversationID(t.Context(), "conv-worker-trace")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithMessageID(ctx, "msg-worker-trace")

	execute := findSubAgentTool(t, service.tools, pentToolExecute)
	if _, err := execute.InvokableRun(ctx, `{
		"task":"审计文件上传路径",
		"worker_focus":"文件上传 Worker",
		"mode":"read_only"
	}`); err != nil {
		t.Fatalf("执行 Worker 失败: %v", err)
	}
	planner := findSubAgentTool(t, service.tools, pentToolPlanHypotheses)
	if _, err := planner.InvokableRun(ctx, `{"planning_task":"规划 NET 审计任务"}`); err != nil {
		t.Fatalf("执行 Planner 失败: %v", err)
	}

	details, err := service.db.ListProcessDetails(ctx, "conv-worker-trace", 100)
	if err != nil {
		t.Fatalf("读取过程详情失败: %v", err)
	}
	lifecycle := map[string]map[string]interface{}{}
	for _, detail := range details {
		if detail.EventType == observability.TypeSubagentStarted ||
			detail.EventType == observability.TypeSubagentCompleted {
			key := detail.EventType + ":" + traceString(detail.Data["agentKind"])
			lifecycle[key] = detail.Data
		}
	}
	workerStart := lifecycle[observability.TypeSubagentStarted+":worker"]
	if workerStart == nil ||
		traceString(workerStart["workerFocus"]) != "文件上传 Worker" ||
		!strings.Contains(traceString(workerStart["task"]), "审计文件上传路径") {
		t.Fatalf("Worker 启动记录缺失或内容不完整: %+v", workerStart)
	}
	workerDone := lifecycle[observability.TypeSubagentCompleted+":worker"]
	if workerDone == nil || traceString(workerDone["status"]) != "completed" {
		t.Fatalf("Worker 完成记录缺失: %+v", workerDone)
	}
	if lifecycle[observability.TypeSubagentStarted+":planner"] == nil ||
		lifecycle[observability.TypeSubagentCompleted+":planner"] == nil {
		t.Fatalf("Planner 生命周期记录缺失: %+v", lifecycle)
	}
}

func TestWorkerWaitingForConcurrencyDoesNotCountAsStarted(t *testing.T) {
	service := newSubAgentTestService(t)
	now := time.Now().UTC()
	if err := service.db.CreateConversation(t.Context(), database.Conversation{
		ID: "conv-worker-wait", OwnerUserID: "user-1", Title: "Worker 排队",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	ctx := execctx.WithConversationID(t.Context(), "conv-worker-wait")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithMessageID(ctx, "msg-worker-wait")
	ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	runner := newSubAgentRunner(service)
	runner.sem = make(chan struct{}, 1)
	runner.sem <- struct{}{}
	if _, err := runner.runWithOptions(
		ctx,
		"审计上传路径",
		subagentModeReadOnly,
		"",
		"worker",
		"上传 Worker",
		"",
		"",
		"上传 Worker",
		nil,
	); err == nil {
		t.Fatalf("并发额度等待超时应返回错误")
	}
	lifecycle, err := service.db.ListAgentLifecycleDetails(t.Context(), "conv-worker-wait", []string{"msg-worker-wait"})
	if err != nil {
		t.Fatalf("读取生命周期失败: %v", err)
	}
	if len(lifecycle) != 0 {
		t.Fatalf("未获得并发额度的 Worker 不应记录为已启动: %+v", lifecycle)
	}
}

func traceString(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func TestEventAgentDataIncludesSubagentIdentity(t *testing.T) {
	ctx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID:           "planner-1",
		Name:         "Planner",
		Kind:         "planner",
		ParentID:     "mainagent",
		IntentID:     "intent-7",
		HypothesisID: "hypothesis-3",
		Mode:         subagentModeReadWrite,
	})
	data := withAgentData(ctx, map[string]interface{}{"tool": "project_plan_hypotheses"})
	if data["agentId"] != "planner-1" || data["agentName"] != "Planner" || data["agentKind"] != "planner" {
		t.Fatalf("Agent 身份字段异常: %+v", data)
	}
	if data["parentAgentId"] != "mainagent" || data["intentId"] != "intent-7" || data["hypothesisId"] != "hypothesis-3" {
		t.Fatalf("Agent 关联字段异常: %+v", data)
	}
	if data["capabilityMode"] != subagentModeReadWrite || data["agentMode"] != nil {
		t.Fatalf("Agent 能力模式字段异常: %+v", data)
	}
	if data["tool"] != "project_plan_hypotheses" {
		t.Fatalf("原有事件字段被覆盖: %+v", data)
	}
}

func TestAgentEventIncludesRunAndAgentIdentity(t *testing.T) {
	ctx := execctx.WithRunMode(context.Background(), agentModeFast)
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID:           "sub-abc123456789",
		Name:         "Worker-ABC123",
		Kind:         "worker",
		ParentID:     "mainagent",
		IntentID:     "intent-1",
		HypothesisID: "hypothesis-1",
		Mode:         subagentModeExecute,
	})
	event := agentEvent(ctx, "tool.started")
	if event.AgentMode != agentModeFast ||
		event.SubagentID != "sub-abc123456789" ||
		event.AgentName != "Worker-ABC123" ||
		event.AgentKind != "worker" ||
		event.ParentAgentID != "mainagent" ||
		event.IntentID != "intent-1" ||
		event.HypothesisID != "hypothesis-1" ||
		event.CapabilityMode != subagentModeExecute {
		t.Fatalf("运行或 Agent 身份字段缺失: %+v", event)
	}
}

func TestTracedSubagentNameUsesStableIDSuffix(t *testing.T) {
	first := tracedSubagentName("Worker", "sub-abcdef123456")
	second := tracedSubagentName("Worker", "sub-fedcba123456")
	if first != "Worker-ABCDEF" || second != "Worker-FEDCBA" || first == second {
		t.Fatalf("子 Agent 名称未唯一化: %q %q", first, second)
	}
}

func TestAgentModeValidationAndRegistry(t *testing.T) {
	if mode, err := ParseAgentMode("FAST"); err != nil || mode != agentModeFast {
		t.Fatalf("Fast Path 模式解析失败: mode=%q err=%v", mode, err)
	}
	if mode, err := ParseAgentMode(""); err != nil || mode != agentModeDeep {
		t.Fatalf("空模式应保持向后兼容的 Deep 模式: mode=%q err=%v", mode, err)
	}
	if mode, err := ParseAgentMode("auto"); err != nil || mode != agentModeAuto {
		t.Fatalf("自动协调模式解析失败: mode=%q err=%v", mode, err)
	}
	if _, err := ParseAgentMode("turbo"); err == nil {
		t.Fatalf("非法模式应返回错误")
	}
	if !isSubAgentEntryToolName(pentToolExecute) || !isSubAgentEntryToolName("pent_agent_status") {
		t.Fatalf("子 Agent 工具注册表未覆盖当前或兼容工具")
	}
	if isSubAgentEntryToolName("pent_agent_unknown") {
		t.Fatalf("未知工具不应仅凭前缀归类为子 Agent 工具")
	}
}

func TestAutomaticAndResolvedAgentModes(t *testing.T) {
	single := missionPlan{
		Mode:           missionModePentest,
		ProjectScope:   false,
		PentestTargets: []string{"https://one.example"},
		Tasks:          []string{"pentest"},
	}
	if mode := automaticAgentMode(single); mode != agentModeFast {
		t.Fatalf("单目标简单任务应选择单 Agent，实际 %s", mode)
	}
	multiple := missionPlan{
		Mode:           missionModePentest,
		PentestTargets: []string{"https://one.example", "https://two.example"},
		Tasks:          []string{"recon", "pentest"},
	}
	if mode := automaticAgentMode(multiple); mode != agentModeDeep {
		t.Fatalf("多目标任务应选择多 Agent，实际 %s", mode)
	}
	if mode := resolveAgentMode(agentModeAuto, agentModeFast, multiple); mode != agentModeFast {
		t.Fatalf("角色默认单 Agent 应覆盖自动推断，实际 %s", mode)
	}
	if mode := resolveAgentMode(agentModeDeep, agentModeFast, single); mode != agentModeDeep {
		t.Fatalf("用户显式选择应覆盖角色默认值，实际 %s", mode)
	}
	if mode := resolveAgentMode(agentModeAuto, agentModeAuto, multiple); mode != agentModeDeep {
		t.Fatalf("自动策略应识别复杂任务，实际 %s", mode)
	}
	codeAudit := missionPlan{
		Mode:        missionModeCodeAudit,
		SourceRoots: []string{"/tmp/source"},
		Tasks:       []string{missionModeCodeAudit},
	}
	if mode := automaticAgentMode(codeAudit); mode != agentModeDeep {
		t.Fatalf("代码审计应默认使用多 Agent 协调，实际 %s", mode)
	}
	retestAll := missionPlan{
		Mode:      missionModeRetest,
		RetestAll: true,
		Tasks:     []string{missionModeRetest},
	}
	if mode := automaticAgentMode(retestAll); mode != agentModeDeep {
		t.Fatalf("批量复测应使用多 Agent 协调，实际 %s", mode)
	}
	singleRetest := missionPlan{
		Mode:             missionModeRetest,
		VulnerabilityIDs: []string{"vul-1"},
		Tasks:            []string{missionModeRetest},
	}
	if mode := automaticAgentMode(singleRetest); mode != agentModeFast {
		t.Fatalf("单漏洞复测应使用单 Agent，实际 %s", mode)
	}
}

func TestLocalAnalysisAllowsSubagentEntryWithoutNetwork(t *testing.T) {
	plan := missionPlan{Mode: missionModeCodeAudit}
	if !missionToolAllowed(plan, missionPhaseSourceAudit, pentToolExecute) {
		t.Fatalf("源码审计阶段应允许调用子 Agent")
	}
	if missionToolAllowed(plan, missionPhaseSourceAudit, "curl") {
		t.Fatalf("源码审计阶段不应允许网络工具")
	}
	if missionStageAllowsNetwork(missionPhaseSourceAudit) {
		t.Fatalf("源码审计阶段不应允许网络访问")
	}
}

func TestPentSubAgentExecute(t *testing.T) {
	service := newSubAgentTestService(t)
	ctx := context.Background()

	execute := findSubAgentTool(t, service.tools, pentToolExecute)
	output, err := execute.InvokableRun(ctx, `{"task":"检查目标"}`)
	if err != nil {
		t.Fatalf("执行子 Agent 失败: %v", err)
	}
	if !strings.Contains(output, "检查目标") {
		t.Fatalf("子 Agent 返回结果异常: %q", output)
	}
}

func TestPentSubAgentExecuteModes(t *testing.T) {
	service := newSubAgentTestService(t)
	execute := findSubAgentTool(t, service.tools, pentToolExecute)
	for _, args := range []string{
		`{"task":"http://target.local","mode":"diagnose"}`,
		`{"task":"SQL 注入，PoC 已确认","mode":"analyze"}`,
	} {
		if _, err := execute.InvokableRun(context.Background(), args); err != nil {
			t.Fatalf("合并后的执行入口失败 %s: %v", args, err)
		}
	}
}

func TestPentSubAgentRejectsEmptyTask(t *testing.T) {
	service := newSubAgentTestService(t)
	execute := findSubAgentTool(t, service.tools, pentToolExecute)
	output, err := execute.InvokableRun(context.Background(), `{"task":"  "}`)
	if err != nil {
		t.Fatalf("工具失败应回传模型而不是中断整轮: %v", err)
	}
	if !strings.Contains(output, "执行失败") || !strings.Contains(output, "task") {
		t.Fatalf("空任务应返回失败说明: %q", output)
	}
}

func TestMockModelTriggersPentToolFromOptions(t *testing.T) {
	chatModel := newMockModel()
	message, err := chatModel.Generate(
		context.Background(),
		[]*schema.Message{schema.UserMessage("请用 pent 子代理检查目标")},
		model.WithTools([]*schema.ToolInfo{{Name: pentToolExecute}}),
	)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	if len(message.ToolCalls) != 1 || message.ToolCalls[0].Function.Name != pentToolExecute {
		t.Fatalf("Mock 应触发 %s，实际: %+v", pentToolExecute, message.ToolCalls)
	}
}
