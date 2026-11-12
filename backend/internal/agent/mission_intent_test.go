package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

func missionTestProject() database.Project {
	return database.Project{
		Name:   "mission-test",
		Scope:  "*.example.com\n*.example.org",
		Status: "active",
	}
}

func missionTestAssets() []database.Asset {
	return []database.Asset{
		{ID: "asset-falcon", Name: "falcon", Value: "https://falcon.example.com"},
		{ID: "asset-api", Name: "api", Value: "https://api.example.org"},
	}
}

type fixedRouterModel struct {
	content     string
	routerCalls int
}

func (m *fixedRouterModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *fixedRouterModel) Generate(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	for _, message := range messages {
		if message != nil && message.Role == schema.System &&
			strings.Contains(message.Content, "任务意图路由器") {
			m.routerCalls++
			return schema.AssistantMessage(m.content, nil), nil
		}
	}
	return schema.AssistantMessage("", nil), nil
}

func (m *fixedRouterModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("", nil)}), nil
}

type flakyRouterModel struct {
	calls int
}

func (m *flakyRouterModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *flakyRouterModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	m.calls++
	if m.calls == 1 {
		return nil, context.DeadlineExceeded
	}
	return schema.AssistantMessage(`{
		"mode":"asset_inventory",
		"tasks":["asset_inventory"],
		"confidence":0.95,
		"reason":"重试后成功"
	}`, nil), nil
}

func (m *flakyRouterModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{schema.AssistantMessage("", nil)}), nil
}

func TestIntentRouterRetriesTransientFailure(t *testing.T) {
	router := &flakyRouterModel{}
	service := &Service{model: router}
	plan, _, err := service.callIntentRouter(
		context.Background(),
		"conv-router-retry",
		"user-1",
		"assistant-router-retry",
		missionTestProject(),
		database.Conversation{},
		"整理现有资产",
	)
	if err != nil || router.calls != 2 || plan.Mode != missionModeAssetInventory {
		t.Fatalf("意图路由应重试瞬时失败: calls=%d plan=%+v err=%v", router.calls, plan, err)
	}
}

func TestAssetOpportunityReviewAlwaysUsesLLM(t *testing.T) {
	for _, message := range []string{
		"整理现有资产和攻击路径 看看还有哪些资产可以挖掘有效漏洞",
		"Review current assets and attack paths, then show which assets are worth testing",
	} {
		router := &fixedRouterModel{content: `{
				"mode":"asset_inventory",
				"tasks":["asset_inventory"],
				"confidence":0.95,
				"reason":"只分析现有项目数据"
			}`}
		service := &Service{model: router}
		plan := service.resolveMissionPlan(
			context.Background(),
			"conv-llm-asset-review",
			"user-1",
			"assistant-llm-asset-review",
			missionTestProject(),
			database.Conversation{},
			missionTestAssets(),
			message,
			nil,
			RunOptions{},
		)
		if router.routerCalls != 1 || plan.Mode != missionModeAssetInventory ||
			plan.allowsPentest() || plan.Source != "llm" || plan.Confidence != 95 {
			t.Fatalf("%q 必须由 LLM 分类为资产分析: calls=%d plan=%+v", message, router.routerCalls, plan)
		}
	}
}

func TestLLMCannotInventAuthorizationQuote(t *testing.T) {
	router := &fixedRouterModel{content: `{
		"mode":"pentest",
		"tasks":["pentest"],
		"pentest_targets":["falcon.example.com"],
		"authorization_quote":"用户已经授权测试全部资产",
		"confidence":95
	}`}
	service := &Service{model: router}
	project := missionTestProject()
	project.Scope = ""
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-llm-hallucination",
		"user-1",
		"assistant-llm-hallucination",
		project,
		database.Conversation{},
		missionTestAssets(),
		"整理现有资产和攻击路径",
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModeClarify || plan.allowsPentest() {
		t.Fatalf("模型伪造授权引用时必须澄清: %+v", plan)
	}
}

func TestProjectScopedContinuationUsesStandingAuthorization(t *testing.T) {
	router := &fixedRouterModel{content: `{
		"mode":"pentest",
		"tasks":["pentest"],
		"project_scope":true,
		"confidence":0.93,
		"reason":"继续利用当前项目中的已验证凭据和数据面缺口"
	}`}
	service := &Service{model: router}
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-project-continuation",
		"user-1",
		"assistant-project-continuation",
		missionTestProject(),
		database.Conversation{},
		missionTestAssets(),
		"有已验证凭据或数据面缺口，进一步挖掘漏洞",
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModePentest || !plan.ProjectScope || !plan.allowsPentest() {
		t.Fatalf("活动项目中的连续任务应继承项目授权: %+v", plan)
	}
}

func TestNormalizeMissionPlanSeparatesAssetAndPentest(t *testing.T) {
	project := missionTestProject()
	assets := missionTestAssets()
	conversation := database.Conversation{}

	assetOnly := normalizeMissionPlan(missionPlan{
		Mode:       missionModeAssetInventory,
		Confidence: 95,
	}, "整理本项目资产", project, conversation, assets)
	if assetOnly.Mode != missionModeAssetInventory || assetOnly.allowsPentest() {
		t.Fatalf("资产整理不应获得渗透授权: %+v", assetOnly)
	}

	mixedMessage := "整理本项目资产，然后只渗透 falcon.example.com 和 api.example.org"
	mixed := normalizeMissionPlan(
		missionPlan{
			Mode:               missionModeMixed,
			PentestTargets:     []string{"falcon.example.com", "api.example.org"},
			AuthorizationQuote: "只渗透 falcon.example.com 和 api.example.org",
			Confidence:         96,
		},
		mixedMessage,
		project,
		conversation,
		assets,
	)
	if mixed.Mode != missionModeMixed || !mixed.allowsPentest() {
		t.Fatalf("混合任务识别错误: %+v", mixed)
	}
	if len(mixed.PentestTargets) != 2 {
		t.Fatalf("应提取两个明确目标: %+v", mixed.PentestTargets)
	}
}

func TestActiveProjectScopeAuthorizesPentest(t *testing.T) {
	project := missionTestProject()
	assets := missionTestAssets()
	conversation := database.Conversation{AssetID: "asset-falcon"}

	plan := normalizeMissionPlan(missionPlan{
		Mode:           missionModePentest,
		PentestTargets: []string{"falcon.example.com"},
		Confidence:     95,
	}, "整理资产", project, conversation, assets)
	if plan.Mode != missionModePentest || !plan.allowsPentest() {
		t.Fatalf("活动项目范围应提供持续授权: %+v", plan)
	}
}

func TestNormalizeMissionPlanRejectsOutOfScopeTarget(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:               missionModePentest,
		PentestTargets:     []string{"evil.example.net"},
		AuthorizationQuote: "渗透 evil.example.net",
		Confidence:         95,
	}, "渗透 evil.example.net", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeClarify {
		t.Fatalf("范围外目标应要求澄清: %+v", plan)
	}
}

func TestRouterCannotAddTargetsBeyondUserRequest(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:               missionModePentest,
		PentestTargets:     []string{"falcon.example.com", "api.example.org"},
		AuthorizationQuote: "只渗透 falcon.example.com",
		Confidence:         95,
	}, "只渗透 falcon.example.com", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeClarify {
		t.Fatalf("Router 擅自增加目标时必须要求澄清: %+v", plan)
	}
}

func TestProjectScopeUsesActiveProjectAuthorization(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:         missionModePentest,
		ProjectScope: true,
		Confidence:   95,
	}, "继续挖掘当前项目漏洞", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModePentest || !plan.ProjectScope {
		t.Fatalf("活动项目范围应允许项目级测试: %+v", plan)
	}
	project := missionTestProject()
	project.Scope = ""
	plan = normalizeMissionPlan(missionPlan{
		Mode:         missionModePentest,
		ProjectScope: true,
		Confidence:   95,
	}, "请测试整个项目", project, database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeClarify {
		t.Fatalf("空项目范围不能作为持续授权: %+v", plan)
	}
}

func TestCurrentTurnAuthorizedRangeExtendsProjectScope(t *testing.T) {
	message := "使用 10.20.30.10、10.20.30.11 和所有已知域名做 Host 碰撞。授权所有内网ip：10.20.*.*"
	plan := normalizeMissionPlan(missionPlan{
		Mode:               missionModePentest,
		PentestTargets:     []string{"10.20.30.10", "10.20.30.11"},
		AuthorizationQuote: "授权所有内网ip：10.20.*.*",
		AuthorizedScopes:   []string{"10.20.*.*"},
		Confidence:         0.95,
	}, message, missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModePentest ||
		len(plan.AuthorizedScopes) != 1 ||
		plan.AuthorizedScopes[0] != "10.20.0.0/16" {
		t.Fatalf("本轮授权范围解析失败: %+v", plan)
	}
	scope := missionScopeFromPlan(context.Background(), plan, missionTestAssets())
	if !missionScopeIncludesTarget(scope, "10.20.30.11") ||
		!missionScopeIncludesTarget(scope, "10.20.200.1") {
		t.Fatalf("Mission 范围应覆盖本轮授权的内网段: %+v", scope)
	}
}

func TestLLMAssetClassificationIsNotOverriddenByWords(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:       missionModeAssetInventory,
		Confidence: 95,
	}, "不要扫描漏洞，只整理本项目资产", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeAssetInventory || plan.allowsPentest() {
		t.Fatalf("LLM 资产分类不应被关键词覆盖: %+v", plan)
	}
}

func TestLLMPentestClassificationUsesVerifiedQuote(t *testing.T) {
	for _, item := range []struct {
		message string
		quote   string
	}{
		{"falcon.example.com 重点挖掘漏洞", "重点挖掘漏洞"},
		{"Please pentest falcon.example.com for vulnerabilities", "Please pentest falcon.example.com"},
	} {
		plan := normalizeMissionPlan(missionPlan{
			Mode:               missionModePentest,
			PentestTargets:     []string{"falcon.example.com"},
			AuthorizationQuote: item.quote,
			Confidence:         95,
		}, item.message, missionTestProject(), database.Conversation{}, missionTestAssets())
		if plan.Mode != missionModePentest || !plan.allowsPentest() {
			t.Fatalf("%q 的 LLM 渗透分类应保留: %+v", item.message, plan)
		}
	}
}

func TestLLMAssetAnalysisDoesNotNeedPentestQuote(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:       missionModeAssetInventory,
		Confidence: 95,
	}, "Review current assets and show which ones may be worth testing", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeAssetInventory || plan.allowsPentest() {
		t.Fatalf("英文资产分析应保持只读模式: %+v", plan)
	}
}

func TestLLMGeneralClassificationIsNotOverriddenByKeywords(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:       missionModeGeneral,
		Confidence: 95,
		Reason:     "普通查询",
	}, "falcon.example.com重点挖掘漏洞", missionTestProject(), database.Conversation{}, missionTestAssets())
	if plan.Mode != missionModeGeneral {
		t.Fatalf("LLM 模式不应被关键词覆盖: %+v", plan)
	}
}

func TestRouterFailureUsesDefaultProjectWork(t *testing.T) {
	service := &Service{model: &emptyThenFinalModel{}}
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-router-failure",
		"user-1",
		"assistant-router-failure",
		missionTestProject(),
		database.Conversation{},
		missionTestAssets(),
		"falcon.example.com 安全问题",
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModePentest || !plan.ProjectScope ||
		plan.Source != "llm_fallback" || plan.RouterError == "" {
		t.Fatalf("Router 失败时应进入默认项目工作: %+v", plan)
	}
}

func TestRouterFailureUsesCurrentTurnAuthorization(t *testing.T) {
	service := &Service{model: &emptyThenFinalModel{}}
	project := missionTestProject()
	project.Scope = ""
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-router-fallback-scope",
		"user-1",
		"assistant-router-fallback-scope",
		project,
		database.Conversation{},
		missionTestAssets(),
		"对 10.20.*.* 做 Host 碰撞",
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModePentest || !plan.allowsPentest() ||
		len(plan.AuthorizedScopes) != 1 || plan.AuthorizedScopes[0] != "10.20.0.0/16" {
		t.Fatalf("Router 失败时应使用本轮显式授权范围: %+v", plan)
	}
}

func TestRouterFailureUsesGeneralWhenNoAuthorizationExists(t *testing.T) {
	service := &Service{model: &emptyThenFinalModel{}}
	project := missionTestProject()
	project.Scope = ""
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-router-fallback-general",
		"user-1",
		"assistant-router-fallback-general",
		project,
		database.Conversation{},
		nil,
		"解释项目状态",
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModeGeneral || plan.allowsPentest() {
		t.Fatalf("无授权时应进入普通项目工作: %+v", plan)
	}
}

func TestProjectScopeDoesNotAuthorizeUnscopedAsset(t *testing.T) {
	if missionTargetAllowed("internal.corp", missionTestProject().Scope) {
		t.Fatalf("资产库中的范围外目标不能自动成为授权目标")
	}
}

func TestScopedTargetGuardAllowsUnresolvedTargets(t *testing.T) {
	service := &Service{}
	ctx := withMissionExecution(context.Background(), missionExecution{
		Plan: missionPlan{
			Mode:           missionModePentest,
			PentestTargets: []string{"falcon.example.com"},
		},
		Phase: missionPhasePentest,
		Scope: missionScope{
			Hosts:  []string{"falcon.example.com"},
			Active: true,
		},
	})
	if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "nmap -iL targets.txt",
	}); !allowed {
		t.Fatalf("无法静态解析目标时不应直接拒绝")
	}
}

func TestScopedSubagentHandoffAllowsUnresolvedTarget(t *testing.T) {
	service := &Service{}
	ctx := withMissionExecution(context.Background(), missionExecution{
		Plan: missionPlan{
			Mode:           missionModePentest,
			PentestTargets: []string{"falcon.example.com"},
		},
		Phase:     missionPhasePentest,
		AgentMode: agentModeDeep,
		Scope: missionScope{
			Hosts:  []string{"falcon.example.com"},
			Active: true,
		},
	})
	if allowed, _ := service.missionToolDecision(ctx, pentToolExecute, map[string]interface{}{
		"task": "继续深入检查所有接口",
	}); !allowed {
		t.Fatalf("Deep Path 移交任务无法静态解析目标时不应拒绝")
	}
}

func TestProjectWriteIntentUsesOnlyProjectTools(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:       missionModeProjectWrite,
		WriteTools: []string{"project_update_finding"},
		Confidence: 95,
	},
		"更新漏洞描述并保存",
		missionTestProject(),
		database.Conversation{},
		missionTestAssets(),
	)
	if plan.Mode != missionModeProjectWrite || plan.allowsPentest() {
		t.Fatalf("普通项目写任务识别错误: %+v", plan)
	}
	service := &Service{tools: []tool.BaseTool{
		&jsonTool{name: "project_update_finding"},
		&jsonTool{name: "project_list_findings"},
		&jsonTool{name: "exec"},
	}}
	names := missionToolNames(t, service.activeToolsForMission(
		context.Background(),
		agentModeFast,
		plan,
		missionPhaseGeneral,
	))
	if !names["project_update_finding"] || names["exec"] {
		t.Fatalf("项目写模式工具白名单错误: %+v", names)
	}
}

func TestProjectWriteFinalizationRequiresMutation(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:       missionModeProjectWrite,
			WriteTools: []string{"project_update_finding"},
		},
		Phase: missionPhaseGeneral,
	})
	capture := &runCapture{}
	capture.recordToolCall("read-call", "project_list_findings")
	capture.recordToolResult("read-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"已经完成更新。",
	)
	if decision.Allowed {
		t.Fatalf("没有实际项目写操作时不应最终化")
	}
	capture.recordToolCall("write-call", "project_update_finding")
	capture.recordToolResult("write-call")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"已经完成更新。",
	)
	if !decision.Allowed {
		t.Fatalf("实际执行项目写操作后应允许最终化: %+v", decision.Reasons)
	}
}

func TestUnsupportedDestructiveRequestDoesNotEnterProjectWriteMode(t *testing.T) {
	plan := normalizeMissionPlan(missionPlan{
		Mode:       missionModeProjectWrite,
		WriteTools: []string{"project_delete_finding"},
		Confidence: 95,
	},
		"删除漏洞记录",
		missionTestProject(),
		database.Conversation{},
		missionTestAssets(),
	)
	if plan.Mode != missionModeClarify || plan.allowsPentest() {
		t.Fatalf("没有受支持工具的写请求必须澄清: %+v", plan)
	}
}

func TestExtendedMissionIntentModes(t *testing.T) {
	sourceRoot := t.TempDir()
	appPath := filepath.Join(t.TempDir(), "demo.apk")
	if err := os.WriteFile(appPath, []byte("apk"), 0o600); err != nil {
		t.Fatalf("创建 App 测试文件失败: %v", err)
	}
	testCases := []struct {
		message string
		mode    string
		stages  []string
		quote   string
	}{
		{
			message: fmt.Sprintf("审计代码目录 %s", sourceRoot),
			mode:    missionModeCodeAudit,
			stages:  []string{missionPhaseSourceAudit},
		},
		{
			message: fmt.Sprintf("代码审计 %s，然后验证 falcon.example.com 的漏洞", sourceRoot),
			mode:    missionModeCodeValidate,
			stages:  []string{missionPhaseSourceAudit, missionPhaseRuntimeValidate},
			quote:   "验证 falcon.example.com 的漏洞",
		},
		{
			message: "复测漏洞 VUL-1234",
			mode:    missionModeRetest,
			stages:  []string{missionPhaseRetest},
			quote:   "复测漏洞 VUL-1234",
		},
		{
			message: fmt.Sprintf("验证 APK %s", appPath),
			mode:    missionModeAppValidation,
			stages:  []string{missionPhaseAppStatic},
		},
		{
			message: fmt.Sprintf("验证 APK %s 并检查后端 falcon.example.com", appPath),
			mode:    missionModeAppValidation,
			stages: []string{
				missionPhaseAppStatic,
				missionPhaseAppRuntime,
				missionPhaseBackendValidate,
			},
			quote: "检查后端 falcon.example.com",
		},
	}
	for _, testCase := range testCases {
		plan := normalizeMissionPlan(missionPlan{
			Mode:               testCase.mode,
			Stages:             testCase.stages,
			AuthorizationQuote: testCase.quote,
			Confidence:         95,
		},
			testCase.message,
			missionTestProject(),
			database.Conversation{},
			missionTestAssets(),
		)
		if plan.Mode != testCase.mode {
			t.Fatalf("%q 模式错误: %+v", testCase.message, plan)
		}
		if strings.Join(plan.missionStages(), ",") != strings.Join(testCase.stages, ",") {
			t.Fatalf("%q 阶段错误: %+v", testCase.message, plan.missionStages())
		}
	}
}

func TestExtendedMissionModesRequireInputs(t *testing.T) {
	for _, testCase := range []struct {
		message string
		mode    string
	}{
		{"帮我审计代码", missionModeCodeAudit},
		{"代码审计后验证漏洞", missionModeCodeValidate},
		{"复测漏洞", missionModeRetest},
		{"验证移动应用", missionModeAppValidation},
	} {
		plan := normalizeMissionPlan(missionPlan{
			Mode:       testCase.mode,
			Confidence: 95,
		},
			testCase.message,
			missionTestProject(),
			database.Conversation{},
			missionTestAssets(),
		)
		if plan.Mode != missionModeClarify {
			t.Fatalf("%q 缺少必要输入时应澄清: %+v", testCase.message, plan)
		}
	}
}

func TestSpecificFindingAuditBindsUniqueFindingAndLocksBudget(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	findingID := "vuln-bounded-finding"
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          findingID,
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "测试越权漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "https://app.example.com/api/user",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建测试漏洞失败: %v", err)
	}

	plan := service.bindMissionFindingReference(
		ctx,
		"project-tools",
		"user-1",
		"那你现在来审计，看这个洞是否真实存在",
		missionPlan{
			Mode:        missionModeCodeAudit,
			FindingIDs:  []string{findingID},
			MaxSegments: 20,
		},
	)
	if plan.Mode != missionModeCodeAudit || !plan.boundedFindingAudit() ||
		len(plan.FindingIDs) != 1 || plan.FindingIDs[0] != findingID ||
		plan.MaxSegments != boundedFindingMaxSegments ||
		plan.MaxToolCalls != boundedFindingMaxToolCalls ||
		plan.AllowFollowUps {
		t.Fatalf("单漏洞核验应绑定唯一漏洞并锁定预算: %+v", plan)
	}
	if mode := resolveAgentMode(agentModeDeep, agentModeDeep, plan); mode != agentModeFast {
		t.Fatalf("单漏洞核验应强制 Fast Path，实际 %s", mode)
	}
	boundedCtx := withMissionExecution(ctx, missionExecution{
		Plan:      plan,
		Phase:     missionPhaseSourceAudit,
		AgentMode: agentModeFast,
	})
	if !missionSuppressesAutomaticFollowUps(boundedCtx) {
		t.Fatal("单漏洞核验必须禁止自动派生后续意图")
	}
}

func TestSpecificFindingReferenceRejectsMissingOrInvalidFinding(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	for _, findingID := range []string{"", "conv-tools", "0123456789abcdef0123456789abcdef"} {
		findingIDs := []string{}
		if findingID != "" {
			findingIDs = []string{findingID}
		}
		plan := service.bindMissionFindingReference(
			ctx,
			"project-tools",
			"user-1",
			"那你现在来审计，看这个洞是否真实存在",
			missionPlan{
				Mode:       missionModeCodeAudit,
				FindingIDs: findingIDs,
			},
		)
		if plan.Mode != missionModeClarify {
			t.Fatalf("指代不明的漏洞引用必须澄清，input=%q plan=%+v", findingID, plan)
		}
	}
}

func TestSpecificFindingReferenceRejectsNonAuditMode(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	plan := service.bindMissionFindingReference(
		ctx,
		"project-tools",
		"user-1",
		"看看这个洞是真的吗",
		missionPlan{Mode: missionModeGeneral},
	)
	if plan.Mode != missionModeClarify {
		t.Fatalf("引用已有漏洞但被误分类为普通任务时必须澄清: %+v", plan)
	}
}

func TestRetestModeSkipsCodeAuditFindingBinder(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	plan := service.bindMissionFindingReference(
		ctx,
		"project-tools",
		"user-1",
		"复测该漏洞，漏洞 ID：24c849ca11237e6f8700c609cc011c1b",
		missionPlan{
			Mode:             missionModeRetest,
			VulnerabilityIDs: []string{"24c849ca11237e6f8700c609cc011c1b"},
			PentestTargets:   []string{"10.8.0.61"},
		},
	)
	if plan.Mode != missionModeRetest ||
		len(plan.VulnerabilityIDs) != 1 ||
		len(plan.PentestTargets) != 1 {
		t.Fatalf("复测模式不应被代码审计 Finding 绑定转成澄清: %+v", plan)
	}
}

func TestMissionClarificationMessageIsSpecific(t *testing.T) {
	message := missionClarificationMessage(missionPlan{
		Mode:   missionModeClarify,
		Reason: "漏洞复测需要明确提供漏洞 ID",
	})
	if message != "漏洞复测需要明确提供漏洞 ID。" {
		t.Fatalf("澄清消息应只返回具体原因: %q", message)
	}
	if strings.Contains(message, "需要先明确任务边界") ||
		strings.Contains(message, "资产整理、项目数据修改") {
		t.Fatalf("不应返回通用任务分类菜单: %q", message)
	}
}

func TestLegacyOpenCodeAuditResumeRequiresFindingBinding(t *testing.T) {
	service := &Service{}
	state := &missionProgressState{
		IntentPlan: &missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{"/tmp/source.zip"},
			Confidence:  95,
		},
		MissionPhase: missionPhaseSourceAudit,
	}
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-legacy-resume",
		"user-1",
		"assistant-legacy-resume",
		missionTestProject(),
		database.Conversation{},
		missionTestAssets(),
		"继续",
		state,
		RunOptions{ResumeOf: "run-legacy"},
	)
	if plan.Mode != missionModeClarify {
		t.Fatalf("旧开放式代码审计恢复必须要求重新绑定具体漏洞: %+v", plan)
	}
}

func TestRecentMissionFindingsUsesMinimalFields(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-minimal-router-data",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "最小化候选",
		Severity:    "high",
		Status:      "open",
		Target:      "https://app.example.com/api/user",
		Description: "不应发送给意图路由器的长描述",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建测试漏洞失败: %v", err)
	}
	items := service.recentMissionFindings(ctx, "project-tools", "user-1")
	if len(items) != 1 {
		t.Fatalf("候选漏洞数量错误: %+v", items)
	}
	if _, exists := items[0]["description"]; exists {
		t.Fatalf("意图路由器不应收到漏洞描述: %+v", items[0])
	}
	for _, field := range []string{"id", "title", "type", "target", "status"} {
		if _, exists := items[0][field]; !exists {
			t.Fatalf("缺少最小候选字段 %s: %+v", field, items[0])
		}
	}
}

func TestMissionInputPathBoundary(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "tmp", "workspace", "conv-path", "src")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	valid := service.validateMissionInputPaths(context.Background(), "conv-path", missionPlan{
		Mode:        missionModeCodeAudit,
		SourceRoots: []string{sourceDir},
	})
	if valid.Mode == missionModeClarify {
		t.Fatalf("合法源码目录不应被拒绝: %+v", valid)
	}
	outside := t.TempDir()
	invalid := service.validateMissionInputPaths(context.Background(), "conv-path", missionPlan{
		Mode:        missionModeCodeAudit,
		SourceRoots: []string{outside},
	})
	if invalid.Mode != missionModeClarify {
		t.Fatalf("存储根目录外路径必须拒绝: %+v", invalid)
	}
}

func TestMissionPolicyRejectsRootOutputWithWorkspaceSuggestion(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "tmp", "workspace", "conv-strings", "src", "bin")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), "conv-strings")
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{filepath.Dir(source)},
		},
		Phase: missionPhaseSourceAudit,
	})
	allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "mkdir -p /strings_out && strings target.dll > /strings_out/result.txt",
	})
	if allowed {
		t.Fatal("根目录输出路径必须被 Mission Policy 拒绝")
	}
	if !strings.Contains(reason, "本地路径超出") ||
		!strings.Contains(reason, "$SOPHON_WORKSPACE/strings_out") {
		t.Fatalf("拒绝原因应给出工作区修复建议: %s", reason)
	}
}

func TestMissionPolicyAllowsRegexPathsInAwkPatterns(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "tmp", "workspace", "conv-awk", "src")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), "conv-awk")
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{source},
		},
		Phase: missionPhaseSourceAudit,
	})
	allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": `cd "$SOPHON_WORKSPACE" && awk -F' -> ' '/NewCode\\.Core\\.Web/{print $1}' out/ref_newcode.txt | sort -u | head -20; echo "=== who references Core.Web types ==="; grep -o "NewCode\\.Core\\.Web\\.[A-Za-z]*" out/ref_newcode.txt | sort | uniq -c | sort -rn | head -20`,
	})
	if !allowed {
		t.Fatalf("awk/grep 正则中的路径片段不应被误判为本地绝对路径: %s", reason)
	}
	for _, command := range []string{
		`cat /tmp/outside*`,
		`sed -f '/tmp/script.sed' out/ref_newcode.txt`,
	} {
		allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
			"command": command,
		})
		if allowed {
			t.Fatalf("真实工作区外路径仍必须拒绝: %s", command)
		}
		if !strings.Contains(reason, "本地路径超出") {
			t.Fatalf("真实路径拒绝原因不正确: %s", reason)
		}
	}
}

func TestMissionPolicyAllowsVariableSuffixPaths(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "tmp", "workspace", "conv-variable", "src")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), "conv-variable")
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{source},
		},
		Phase: missionPhaseSourceAudit,
	})
	for _, command := range []string{
		`ls "$W"/src`,
		`find "${WORKSPACE}"/evidence -maxdepth 1`,
	} {
		if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
			"command": command,
		}); !allowed {
			t.Fatalf("变量后缀路径不应被误判: %s\n%s", command, reason)
		}
	}
	for _, command := range []string{
		"cat /etc/passwd",
		"cat /root/secret",
		"cat /src",
	} {
		if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
			"command": command,
		}); allowed {
			t.Fatalf("真实工作区外路径仍必须拒绝: %s", command)
		}
	}
}

func TestMissionPolicyAllowsConversationScopedSourcePaths(t *testing.T) {
	root := t.TempDir()
	conversationID := "conv-scoped"
	workspace := filepath.Join(root, "tmp", "workspace", conversationID)
	uploads := filepath.Join(root, "chat_uploads", conversationID)
	artifacts := filepath.Join(root, "data", "conversation_artifacts", conversationID)
	otherUploads := filepath.Join(root, "chat_uploads", "conv-other")
	for _, dir := range []string{workspace, uploads, artifacts, otherUploads} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
	}
	sourceZip := filepath.Join(uploads, "WebSite.zip")
	if err := os.WriteFile(sourceZip, []byte("zip"), 0o600); err != nil {
		t.Fatalf("写入源码包失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), conversationID)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{sourceZip},
		},
		Phase:     missionPhaseSourceAudit,
		AgentMode: agentModeDeep,
	})
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-scoped", Kind: "worker", Mode: subagentModeExecute, Depth: 1,
	})
	guidance := service.missionSourceAccessGuidance(ctx)
	for _, want := range []string{uploads, workspace, sourceZip, `unzip -q ` + sourceZip} {
		if !strings.Contains(guidance, want) {
			t.Fatalf("Worker 源码访问提示缺少 %q: %s", want, guidance)
		}
	}
	allowedCommands := []string{
		"ls -la " + uploads,
		"unzip -l " + sourceZip,
		`unzip -q ` + sourceZip + ` -d "$SOPHON_WORKSPACE/src"`,
		"find " + uploads + " -maxdepth 2 -type f",
		"ls -la " + artifacts,
		"cp " + sourceZip + " " + filepath.Join(workspace, "source.zip"),
	}
	for _, command := range allowedCommands {
		if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
			"command": command,
		}); !allowed {
			t.Fatalf("当前会话源码路径应允许: %s\n%s", command, reason)
		}
	}
	deniedCommands := []string{
		"cat " + filepath.Join(root, "config.yml"),
		"ls -la " + otherUploads,
		"find " + root,
		"echo blocked > " + filepath.Join(uploads, "new.txt"),
		"cp " + filepath.Join(workspace, "source.zip") + " " + filepath.Join(uploads, "copy.zip"),
		`cd "$SOPHON_WORKSPACE" && ls .. && ls ../..`,
	}
	for _, command := range deniedCommands {
		if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
			"command": command,
		}); allowed {
			t.Fatalf("跨会话、敏感路径或非工作区写入必须拒绝: %s", command)
		}
	}
}

func TestCodeAuditStageOnlyBlocksAllUnauthorizedTargets(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "tmp", "workspace", "conv-audit", "src")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), "conv-audit")
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{source},
			Stages:      []string{missionPhaseSourceAudit},
		},
		Phase: missionPhaseSourceAudit,
		Scope: missionScope{
			Hosts:  []string{"falcon.example.com"},
			Active: true,
		},
	})
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "grep -R TODO " + source,
	}); !allowed {
		t.Fatalf("本地代码检索应允许: %s", reason)
	}
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl https://falcon.example.com/",
	}); !allowed {
		t.Fatalf("代码审计阶段应允许授权范围内网络请求: %s", reason)
	}
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl https://falcon.example.com/; curl https://evil.example/",
	}); !allowed {
		t.Fatalf("包含授权目标时应允许: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl https://evil.example/",
	}); allowed {
		t.Fatalf("全部目标未授权时必须拒绝")
	}
}

func TestDeepCodeAuditMainAgentIsCoordinatorOnly(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "tmp", "workspace", "conv-coordinator", "src")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatalf("创建源码目录失败: %v", err)
	}
	service := &Service{cfg: config.Config{Storage: config.StorageConfig{ArtifactRoot: root}}}
	ctx := execctx.WithConversationID(context.Background(), "conv-coordinator")
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:        missionModeCodeAudit,
			SourceRoots: []string{source},
		},
		Phase:     missionPhaseSourceAudit,
		AgentMode: agentModeDeep,
	})
	for _, toolName := range []string{"exec", "execute-python-script", readSkillToolName, mcpUseToolName, pentToolExecute} {
		allowed, reason := service.missionToolDecision(ctx, toolName, map[string]interface{}{
			"command": "ls", "script": "print('x')", "name": "dotnet-code-audit",
		})
		if allowed {
			t.Fatalf("代码审计主 Agent 不应直接执行 %s", toolName)
		}
		if !strings.Contains(reason, "只负责规划和调度") {
			t.Fatalf("%s 拒绝原因不正确: %s", toolName, reason)
		}
	}
	for _, toolName := range []string{
		pentToolPlanHypotheses,
		pentToolExecuteHypothesis,
		"project_list_hypotheses",
		"read_artifact",
	} {
		allowed, reason := service.missionToolDecision(ctx, toolName, map[string]interface{}{})
		if !allowed {
			t.Fatalf("主 Agent 应允许协调工具 %s: %s", toolName, reason)
		}
	}

	workerCtx := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-1", Kind: "worker", Mode: subagentModeExecute, Depth: 1,
	})
	if allowed, reason := service.missionToolDecision(workerCtx, "exec", map[string]interface{}{
		"command": "grep -R TODO " + source,
	}); !allowed {
		t.Fatalf("Worker 应保留本地审计执行权限: %s", reason)
	}
}

func TestCodeAuditFinalizationRequiresLocalAnalysis(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  missionPlan{Mode: missionModeCodeAudit},
		Phase: missionPhaseSourceAudit,
	})
	capture := &runCapture{}
	capture.recordToolCall("memory-call", "project_query_memory")
	capture.recordToolResult("memory-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"代码审计完成。",
	)
	if decision.Allowed {
		t.Fatalf("没有执行本地源码分析时不应最终化")
	}
	capture.recordToolCall("local-analysis", "exec")
	capture.recordToolResult("local-analysis")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"代码审计完成。",
	)
	if !decision.Allowed {
		t.Fatalf("本地源码分析后应允许代码审计最终化: %+v", decision.Reasons)
	}
	plannerOnly := &runCapture{}
	plannerOnly.recordToolCall("planner-call", pentToolPlanHypotheses)
	plannerOnly.recordToolResult("planner-call")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		plannerOnly,
		"代码审计完成。",
	)
	if decision.Allowed {
		t.Fatalf("只有 Planner、没有 Worker 执行时不应允许代码审计最终化")
	}
	delegated := &runCapture{}
	delegated.recordToolCall("delegated-analysis", pentToolExecuteHypothesis)
	delegated.recordToolResult("delegated-analysis")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		delegated,
		"代码审计完成。",
	)
	if !decision.Allowed {
		t.Fatalf("通过 Worker 执行源码分析后应允许代码审计最终化: %+v", decision.Reasons)
	}
}

func TestRetestMissionLoadsOriginalVulnerabilityTarget(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-retest-source",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "复测源漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "https://app.example.com/api/user",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	plan := service.hydrateMissionPlan(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		missionTestAssets(),
		missionPlan{
			Mode:             missionModeRetest,
			VulnerabilityIDs: []string{"vuln-retest-source"},
		},
	)
	if plan.Mode == missionModeClarify ||
		len(plan.PentestTargets) != 1 ||
		plan.PentestTargets[0] != "app.example.com" ||
		len(plan.RetestIDs) != 1 {
		t.Fatalf("复测任务应加载原漏洞目标: %+v", plan)
	}
}

func TestRetestMissionUsesExplicitTargetWhenStoredTargetIsSourcePath(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	const findingID = "vuln-retest-source-path"
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          findingID,
		ProjectID:   "project-tools",
		AssetID:     "asset-with-code-path",
		OwnerUserID: "user-1",
		Title:       "源码路径型漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "src/WebSite/App_Data/Common.config:350 → SRM/ScpSupRegHandler",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	plan := service.hydrateMissionPlan(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		missionTestAssets(),
		missionPlan{
			Mode:             missionModeRetest,
			VulnerabilityIDs: []string{findingID},
			PentestTargets:   []string{"10.8.0.61", "http://10.8.0.61:8000"},
		},
	)
	if plan.Mode == missionModeClarify ||
		len(plan.PentestTargets) != 1 ||
		plan.PentestTargets[0] != "10.8.0.61" ||
		len(plan.RetestIDs) != 1 {
		t.Fatalf("存储目标为源码路径时应改用用户显式复测目标: %+v", plan)
	}
}

func TestRetestAllResolvesEveryProjectVulnerability(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for index, status := range []string{"open", "fixed", "ignored"} {
		if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
			ID:          fmt.Sprintf("vuln-retest-all-%d", index),
			ProjectID:   "project-tools",
			OwnerUserID: "user-1",
			Title:       fmt.Sprintf("批量复测漏洞 %d", index),
			Severity:    "high",
			Status:      status,
			Target:      fmt.Sprintf("https://app.example.com/api/%d", index),
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建漏洞失败: %v", err)
		}
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-retest-all-no-target",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "无目标漏洞",
		Severity:    "low",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建无目标漏洞失败: %v", err)
	}

	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Scope = "*.example.com"
	project.UpdatedAt = now
	if err := service.db.UpdateProject(ctx, *project); err != nil {
		t.Fatalf("更新项目授权范围失败: %v", err)
	}
	conversation, err := service.db.GetConversation(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	router := &fixedRouterModel{content: `{
		"mode":"retest",
		"tasks":["retest"],
		"retest_all":true,
		"confidence":0.95,
		"reason":"复测当前项目全部漏洞"
	}`}
	service.model = router
	plan := service.resolveMissionPlan(
		ctx,
		"conv-tools",
		"user-1",
		"assistant-retest-all",
		*project,
		*conversation,
		missionTestAssets(),
		"对所有漏洞进行复测",
		nil,
		RunOptions{},
	)
	plan = service.hydrateMissionPlan(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		missionTestAssets(),
		plan,
	)
	if plan.Mode != missionModeRetest || len(plan.VulnerabilityIDs) != 3 || len(plan.RetestIDs) != 3 {
		t.Fatalf("项目级批量复测解析错误: %+v", plan)
	}
}

func TestRetestFinalizationRequiresEvidenceAndWriteback(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-retest-final",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "复测最终化漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "https://app.example.com/api/user",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	plan := service.hydrateMissionPlan(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		missionTestAssets(),
		missionPlan{
			Mode:             missionModeRetest,
			VulnerabilityIDs: []string{"vuln-retest-final"},
			Stages:           []string{missionPhaseRetest},
		},
	)
	if plan.Mode == missionModeClarify {
		t.Fatalf("复测计划创建失败: %+v", plan)
	}
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  plan,
		Phase: missionPhaseRetest,
		Scope: missionScope{
			Hosts:  []string{"app.example.com"},
			Active: true,
		},
	})
	capture := &runCapture{}
	capture.recordToolCall("retest-write", "project_retest_finding")
	capture.recordToolResult("retest-write")
	runStartedAt := time.Now().UTC().Add(-time.Second)
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
		"复测结论为 fixed。",
	)
	if decision.Allowed {
		t.Fatalf("没有运行时证据时复测不应最终化")
	}
	executionID := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "curl https://app.example.com/api/user"},
	)
	service.db.FinishToolExecution(ctx, executionID, "HTTP 404，原 PoC 不再复现", nil)
	capture.recordToolCall("retest-probe", "exec")
	capture.recordToolResult("retest-probe")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
		"复测结论为 fixed。",
	)
	if !decision.Allowed {
		t.Fatalf("复测证据和写回齐全后应允许最终化: %+v", decision.Reasons)
	}
}

type usageIntentRouterModel struct{}

func (m *usageIntentRouterModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *usageIntentRouterModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	message := schema.AssistantMessage(`{
		"mode":"general",
		"tasks":["general"],
		"confidence":90,
		"reason":"普通查询"
	}`, nil)
	message.ResponseMeta = &schema.ResponseMeta{
		Usage: &schema.TokenUsage{
			PromptTokens:     120,
			CompletionTokens: 30,
			TotalTokens:      150,
		},
	}
	return message, nil
}

func (m *usageIntentRouterModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return nil, nil
}

func TestIntentRouterRecordsTokenUsage(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/intent-usage.db")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := &Service{db: db, model: &usageIntentRouterModel{}}
	project := missionTestProject()
	conversation := database.Conversation{}
	if err := db.CreateConversation(context.Background(), database.Conversation{
		ID:          "conv-usage",
		OwnerUserID: "user-1",
		Title:       "Router Token 测试",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建测试会话失败: %v", err)
	}
	_, _, err = service.callIntentRouter(
		context.Background(),
		"conv-usage",
		"user-1",
		"assistant-usage",
		project,
		conversation,
		"解释当前项目",
	)
	if err != nil {
		t.Fatalf("Router 调用失败: %v", err)
	}
	var kind string
	var promptTokens, completionTokens, totalTokens int
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT kind, prompt_tokens, completion_tokens, total_tokens
		 FROM token_usage WHERE message_id = ?`,
		"assistant-usage",
	).Scan(&kind, &promptTokens, &completionTokens, &totalTokens); err != nil {
		t.Fatalf("读取 Router Token 记录失败: %v", err)
	}
	if kind != "intent_router" || promptTokens != 120 || completionTokens != 30 || totalTokens != 150 {
		t.Fatalf("Router Token 记录错误: kind=%s prompt=%d completion=%d total=%d",
			kind, promptTokens, completionTokens, totalTokens)
	}
}

func TestMissionToolAllowlistPreventsAssetPhaseProbes(t *testing.T) {
	service := &Service{tools: []tool.BaseTool{
		&jsonTool{name: "project_list_assets"},
		&jsonTool{name: "project_insert_assets"},
		&jsonTool{name: "exec"},
		&jsonTool{name: "execute-python-script"},
		&jsonTool{name: pentToolExecute},
		&jsonTool{name: "project_record_test"},
		&jsonTool{name: internetSearchToolName},
	}}
	assetTools := service.activeToolsForMission(
		context.Background(),
		agentModeDeep,
		missionPlan{Mode: missionModeAssetInventory},
		missionPhaseAsset,
	)
	names := missionToolNames(t, assetTools)
	if !names["project_list_assets"] || !names["project_insert_assets"] {
		t.Fatalf("资产工具应保留: %+v", names)
	}
	for _, forbidden := range []string{
		"exec",
		"execute-python-script",
		pentToolExecute,
		"project_record_test",
		internetSearchToolName,
	} {
		if names[forbidden] {
			t.Fatalf("资产阶段不应暴露 %s: %+v", forbidden, names)
		}
	}

	deepPentestTools := service.activeToolsForMission(
		context.Background(),
		agentModeDeep,
		missionPlan{Mode: missionModePentest, PentestTargets: []string{"app.example.com"}},
		missionPhasePentest,
	)
	deepNames := missionToolNames(t, deepPentestTools)
	if deepNames["exec"] || !deepNames[pentToolExecute] || !deepNames[internetSearchToolName] {
		t.Fatalf("Deep Path 应强制通过子 Agent 执行渗透: %+v", deepNames)
	}
}

func TestInternetSearchMissionPolicy(t *testing.T) {
	if !generalMissionToolAllowed(internetSearchToolName) {
		t.Fatal("通用任务应允许互联网搜索")
	}
	if assetInventoryToolAllowed(internetSearchToolName) {
		t.Fatal("资产整理阶段不应允许互联网搜索")
	}
	if localAnalysisToolAllowed(internetSearchToolName) {
		t.Fatal("源码审计阶段不应允许互联网搜索")
	}
	if !missionToolIsNetworkCapable(internetSearchToolName, nil) {
		t.Fatal("互联网搜索必须被识别为网络工具")
	}
	if targets := missionNetworkTargets(internetSearchToolName, map[string]interface{}{
		"query": "example.com CVE",
	}); len(targets) != 0 {
		t.Fatalf("搜索关键词中的域名不应被当作渗透目标: %v", targets)
	}

	service := &Service{}
	generalCtx := withMissionExecution(context.Background(), missionExecution{
		Plan:      missionPlan{Mode: missionModeGeneral},
		Phase:     missionPhaseGeneral,
		AgentMode: agentModeFast,
	})
	if allowed, reason := service.missionToolDecision(generalCtx, internetSearchToolName, map[string]interface{}{
		"query": "CVE-2026 example",
	}); !allowed {
		t.Fatalf("通用任务调用互联网搜索被错误拒绝: %s", reason)
	}

	deepPentestCtx := withMissionExecution(context.Background(), missionExecution{
		Plan:      missionPlan{Mode: missionModePentest, ProjectScope: true},
		Phase:     missionPhasePentest,
		AgentMode: agentModeDeep,
	})
	if allowed, reason := service.missionToolDecision(deepPentestCtx, internetSearchToolName, map[string]interface{}{
		"query": "CVE-2026 example.com",
	}); !allowed {
		t.Fatalf("Deep Path 主 Agent 应允许公开资料搜索: %s", reason)
	}
}

func TestProjectListResourceHonorsMissionPhaseAllowlist(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.cfg.Storage.ArtifactRoot = t.TempDir()
	sourceCtx := withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:         missionModeCodeAudit,
			ProjectScope: true,
		},
		Phase:     missionPhaseSourceAudit,
		AgentMode: agentModeFast,
	})
	if allowed, reason := service.missionToolDecision(sourceCtx, "project_list", map[string]interface{}{
		"resource": "findings",
	}); !allowed {
		t.Fatalf("源码分析阶段应允许查询 findings: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(sourceCtx, "project_list", map[string]interface{}{
		"resource": "chains",
	}); allowed {
		t.Fatal("源码分析阶段不应通过 project_list 查询 chains")
	}
	if _, err := invokeProjectTool(t, service, sourceCtx, "project_list", map[string]interface{}{
		"resource": "chains",
	}); err == nil || !strings.Contains(err.Error(), "Mission Policy 拒绝执行 project_list") {
		t.Fatalf("源码分析阶段实际调用 project_list chains 应被拒绝: %v", err)
	}

	retestCtx := withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:         missionModeRetest,
			ProjectScope: true,
		},
		Phase:     missionPhaseRetest,
		AgentMode: agentModeFast,
	})
	if allowed, reason := service.missionToolDecision(retestCtx, "project_list", map[string]interface{}{
		"resource": "findings",
	}); !allowed {
		t.Fatalf("复测阶段应允许查询 findings: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(retestCtx, "project_list", map[string]interface{}{
		"resource": "assets",
	}); allowed {
		t.Fatal("复测阶段不应通过 project_list 查询 assets")
	}
	if _, err := invokeProjectTool(t, service, retestCtx, "project_list", map[string]interface{}{
		"resource": "assets",
	}); err == nil || !strings.Contains(err.Error(), "Mission Policy 拒绝执行 project_list") {
		t.Fatalf("复测阶段实际调用 project_list assets 应被拒绝: %v", err)
	}
}

func TestProjectGetResourceHonorsMissionPhaseAllowlist(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.cfg.Storage.ArtifactRoot = t.TempDir()
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-project-get-phase",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "阶段测试资产",
		Kind:        "domain",
		Value:       "phase.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建测试资产失败: %v", err)
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-project-get-phase",
		ProjectID:   "project-tools",
		AssetID:     "asset-project-get-phase",
		OwnerUserID: "user-1",
		Title:       "阶段测试漏洞",
		Severity:    "high",
		Status:      "confirmed",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建测试漏洞失败: %v", err)
	}
	retestCtx := withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:         missionModeRetest,
			ProjectScope: true,
		},
		Phase:     missionPhaseRetest,
		AgentMode: agentModeFast,
	})
	if allowed, reason := service.missionToolDecision(retestCtx, "project_get", map[string]interface{}{
		"resource": "finding",
	}); !allowed {
		t.Fatalf("复测阶段应允许读取 finding: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(retestCtx, "project_get", map[string]interface{}{
		"resource": "asset",
	}); allowed {
		t.Fatal("复测阶段不应通过 project_get 读取资产卡片")
	}
	if _, err := invokeProjectTool(t, service, retestCtx, "project_get", map[string]interface{}{
		"resource": "asset",
		"id":       "asset-project-get-phase",
	}); err == nil || !strings.Contains(err.Error(), "Mission Policy 拒绝执行 project_get") {
		t.Fatalf("复测阶段实际调用 project_get asset 应被拒绝: %v", err)
	}
	if output, err := invokeProjectTool(t, service, retestCtx, "project_get", map[string]interface{}{
		"resource": "finding",
		"id":       "vuln-project-get-phase",
	}); err != nil || !strings.Contains(output, "阶段测试漏洞") {
		t.Fatalf("复测阶段实际调用 project_get finding 应成功: %q %v", output, err)
	}

	assetCtx := withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:         missionModeAssetInventory,
			ProjectScope: true,
		},
		Phase:     missionPhaseAsset,
		AgentMode: agentModeFast,
	})
	if allowed, reason := service.missionToolDecision(assetCtx, "project_get", map[string]interface{}{
		"resource": "graph_node",
	}); !allowed {
		t.Fatalf("资产整理阶段应允许读取图谱节点: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(assetCtx, "project_get", map[string]interface{}{
		"resource": "unknown",
	}); allowed {
		t.Fatal("未知 project_get resource 必须在权限检查阶段被拒绝")
	}
}

func TestMissionToolDecisionRestrictsPentestTargets(t *testing.T) {
	service := &Service{}
	ctx := withMissionExecution(context.Background(), missionExecution{
		Plan: missionPlan{
			Mode:           missionModePentest,
			PentestTargets: []string{"falcon.example.com"},
		},
		Phase: missionPhasePentest,
		Scope: missionScope{
			Hosts:  []string{"falcon.example.com"},
			Active: true,
		},
	})
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl -s https://falcon.example.com/falcon/user_info/uid_query",
	}); !allowed {
		t.Fatalf("明确目标应允许: %s", reason)
	}
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": `printf '<svg xmlns="http://www.w3.org/2000/svg"></svg>' > rt.svg; ` +
			`curl -s https://falcon.example.com/health; curl -s https://other.example.com/`,
	}); !allowed {
		t.Fatalf("至少一个目标在授权范围内时应允许: %s", reason)
	}
	if allowed, reason := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": `printf '<svg xmlns="http://www.w3.org/2000/svg"></svg>' > rt.svg; ls -l rt.svg`,
	}); !allowed {
		t.Fatalf("无真实网络目标的本地命令不应触发授权检查: %s", reason)
	}
	if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl -s https://other.example.com/",
	}); allowed {
		t.Fatalf("其他目标必须由 Mission Policy 拒绝")
	}
	if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl -s https://other.example.com/; curl -s https://third.example.com/",
	}); allowed {
		t.Fatalf("全部目标均未授权时必须拒绝")
	}
}

func TestTaskOnlyFinalizationIgnoresProjectCoverage(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "unrelated-open-intent",
		ProjectID:  "project-tools",
		Kind:       "intent",
		Title:      "另一个资产的未完成渗透意图",
		Status:     "open",
		Confidence: 80,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建未完成意图失败: %v", err)
	}
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  missionPlan{Mode: missionModeAssetInventory},
		Phase: missionPhaseAsset,
	})
	capture := &runCapture{}
	capture.recordToolCall("asset-call", "project_list_assets")
	capture.recordToolResult("asset-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"项目资产整理完成。",
	)
	if !decision.Allowed {
		t.Fatalf("资产任务不应被其他渗透意图阻塞: %+v", decision.Reasons)
	}
}

func TestScopedFinalizationDoesNotUseWholeProjectMetricsWithoutAssetID(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ID:        "unrelated-required-test",
		ProjectID: "project-tools",
		AssetID:   "unrelated-asset",
		Dimension: "SQL注入",
		Technique: "boolean",
		Status:    "untested",
		Required:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建范围外测试失败: %v", err)
	}
	executionID := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "curl https://app.example.com"},
	)
	service.db.FinishToolExecution(ctx, executionID, "ok", nil)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan: missionPlan{
			Mode:           missionModePentest,
			PentestTargets: []string{"app.example.com"},
		},
		Phase: missionPhasePentest,
		Scope: missionScope{
			Hosts:  []string{"app.example.com"},
			Active: true,
		},
	})
	capture := &runCapture{}
	capture.recordToolCall("scoped-call", "exec")
	capture.recordToolResult("scoped-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"指定目标验证完成。",
	)
	if !decision.Allowed {
		t.Fatalf("限定目标不应被其他资产未测试项阻塞: %+v", decision.Reasons)
	}
}

func TestMissionScopeAssetMappingUsesExactHost(t *testing.T) {
	scope := missionScopeFromPlan(
		context.Background(),
		missionPlan{PentestTargets: []string{"app.example.com"}},
		[]database.Asset{
			{ID: "asset-right", Value: "https://app.example.com/path"},
			{ID: "asset-wrong", Value: "https://notapp.example.com"},
		},
	)
	if len(scope.AssetIDs) != 1 || scope.AssetIDs[0] != "asset-right" {
		t.Fatalf("资产映射必须使用精确主机匹配: %+v", scope.AssetIDs)
	}
}

func TestMixedAssetPhaseDoesNotHandoffWhileAskingQuestion(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = execctx.WithAutoContinue(ctx, false)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  missionPlan{Mode: missionModeMixed, PentestTargets: []string{"app.example.com"}},
		Phase: missionPhaseAsset,
	})
	capture := &runCapture{}
	capture.recordToolCall("asset-read", "project_list_assets")
	capture.recordToolResult("asset-read")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"资产已整理。需要我继续渗透吗？",
	)
	if !decision.PauseOnQuestion {
		t.Fatalf("资产阶段提问时应暂停，不应自动移交渗透: %+v", decision)
	}
}

type assetInventoryIntentModel struct {
	streamCalls int
}

func (m *assetInventoryIntentModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *assetInventoryIntentModel) Generate(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	for _, message := range messages {
		if message != nil && message.Role == schema.System &&
			strings.Contains(message.Content, "任务意图路由器") {
			return schema.AssistantMessage(`{
				"mode":"asset_inventory",
				"tasks":["asset_inventory"],
				"asset_action":"列出并整理项目资产",
				"confidence":95,
				"reason":"用户只要求整理资产"
			}`, nil), nil
		}
	}
	return schema.AssistantMessage("普通生成", nil), nil
}

func (m *assetInventoryIntentModel) Stream(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	m.streamCalls++
	for _, message := range messages {
		if message != nil && message.Role == schema.Tool {
			return schema.StreamReaderFromArray([]*schema.Message{
				schema.AssistantMessage("项目资产整理完成。", nil),
			}), nil
		}
	}
	return schema.StreamReaderFromArray([]*schema.Message{
		schema.AssistantMessage("", []schema.ToolCall{{
			ID:   "asset-inventory-call",
			Type: "function",
			Function: schema.FunctionCall{
				Name:      "project_list",
				Arguments: `{"resource":"assets","limit":30}`,
			},
		}}),
	}), nil
}

func TestAssetIntentRunEndsWithoutAutonomousPentest(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/asset-intent.db")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-asset-intent",
		OwnerUserID: "user-1",
		Name:        "资产整理",
		Scope:       "*.example.com",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID:          "asset-example",
		ProjectID:   "project-asset-intent",
		OwnerUserID: "user-1",
		Name:        "example",
		Kind:        "url",
		Value:       "https://app.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-asset-intent",
		OwnerUserID: "user-1",
		ProjectID:   "project-asset-intent",
		Title:       "整理资产",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "user-asset-intent",
		ConversationID: "conv-asset-intent",
		Role:           "user",
		Content:        "整理本项目资产",
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "assistant-asset-intent",
		ConversationID: "conv-asset-intent",
		Role:           "assistant",
		Content:        "",
		CreatedAt:      now.Add(time.Millisecond),
	}); err != nil {
		t.Fatalf("写入助手消息失败: %v", err)
	}

	service := &Service{
		db:     db,
		cfg:    config.Config{AgentMaxIterations: 4},
		model:  &assetInventoryIntentModel{},
		events: nil,
	}
	service.tools = newProjectTools(service)
	service.baseTools = append([]tool.BaseTool(nil), service.tools...)
	t.Cleanup(func() {
		if !service.WaitForBackgroundTasks(5 * time.Second) {
			t.Errorf("资产意图测试后台任务未完成")
		}
	})

	result, err := service.RunWithOptions(
		ctx,
		"conv-asset-intent",
		"user-1",
		"assistant-asset-intent",
		nil,
		RunOptions{AgentMode: agentModeDeep},
	)
	if err != nil {
		t.Fatalf("资产整理运行失败: %v", err)
	}
	if !strings.Contains(result, "项目资产整理完成") {
		t.Fatalf("资产结果异常: %q", result)
	}
	run, err := db.GetLatestAgentRun(ctx, "conv-asset-intent")
	if err != nil || run == nil {
		t.Fatalf("读取运行记录失败: %+v %v", run, err)
	}
	if run.Status != database.AgentRunStatusCompleted {
		t.Fatalf("资产任务应正常完成，实际 %s", run.Status)
	}
	details, err := db.ListProcessDetails(ctx, "conv-asset-intent", 100)
	if err != nil {
		t.Fatalf("读取过程详情失败: %v", err)
	}
	foundAssetTool := false
	for _, detail := range details {
		if detail.EventType != "tool_call" {
			continue
		}
		if detail.Message == "project_list" {
			foundAssetTool = true
		}
		if detail.Message == "exec" || strings.HasPrefix(detail.Message, "pent_agent_") {
			t.Fatalf("资产整理阶段不应调用渗透工具: %s", detail.Message)
		}
	}
	if !foundAssetTool {
		t.Fatalf("资产整理应实际调用 project_list")
	}
}

type mixedIntentModel struct {
	streamCalls int
}

func (m *mixedIntentModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *mixedIntentModel) Generate(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	for _, message := range messages {
		if message != nil && message.Role == schema.System &&
			strings.Contains(message.Content, "任务意图路由器") {
			return schema.AssistantMessage(`{
				"mode":"mixed",
					"tasks":["asset_inventory","pentest"],
					"asset_action":"先整理项目资产",
					"pentest_targets":["app.example.com"],
					"authorization_quote":"只渗透 app.example.com",
					"confidence":96,
				"reason":"用户先整理资产，再只测试明确目标"
			}`, nil), nil
		}
	}
	return schema.AssistantMessage("普通生成", nil), nil
}

func (m *mixedIntentModel) Stream(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	m.streamCalls++
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message == nil {
			continue
		}
		if message.Role == schema.User && strings.Contains(message.Content, "【阶段移交】") {
			return schema.StreamReaderFromArray([]*schema.Message{
				schema.AssistantMessage("指定目标渗透完成。", nil),
			}), nil
		}
		if message.Role == schema.Tool {
			return schema.StreamReaderFromArray([]*schema.Message{
				schema.AssistantMessage("项目资产整理完成。", nil),
			}), nil
		}
	}
	return schema.StreamReaderFromArray([]*schema.Message{
		schema.AssistantMessage("", []schema.ToolCall{{
			ID:   "mixed-asset-inventory-call",
			Type: "function",
			Function: schema.FunctionCall{
				Name:      "project_list",
				Arguments: `{"resource":"assets","limit":30}`,
			},
		}}),
	}), nil
}

func TestMixedIntentRunsAssetPhaseBeforeScopedPentest(t *testing.T) {
	db, err := database.Open(t.TempDir() + "/mixed-intent.db")
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-mixed-intent",
		OwnerUserID: "user-1",
		Name:        "混合任务",
		Scope:       "*.example.com",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID:          "asset-mixed",
		ProjectID:   "project-mixed-intent",
		OwnerUserID: "user-1",
		Name:        "app",
		Kind:        "url",
		Value:       "https://app.example.com",
		Status:      "active",
		Criticality: "high",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-mixed-intent",
		OwnerUserID: "user-1",
		ProjectID:   "project-mixed-intent",
		Title:       "整理资产并渗透",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "user-mixed-intent",
		ConversationID: "conv-mixed-intent",
		Role:           "user",
		Content:        "整理本项目资产，然后只渗透 app.example.com",
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "assistant-mixed-intent",
		ConversationID: "conv-mixed-intent",
		Role:           "assistant",
		Content:        "",
		CreatedAt:      now.Add(time.Millisecond),
	}); err != nil {
		t.Fatalf("写入助手消息失败: %v", err)
	}

	if err := db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "other-open-intent",
		ProjectID:  "project-mixed-intent",
		Kind:       "intent",
		Title:      "其他域名未完成意图",
		Status:     "open",
		Confidence: 80,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建其他意图失败: %v", err)
	}

	service := &Service{
		db:    db,
		cfg:   config.Config{AgentMaxIterations: 6},
		model: &mixedIntentModel{},
	}
	service.tools = newProjectTools(service)
	service.baseTools = append([]tool.BaseTool(nil), service.tools...)
	t.Cleanup(func() {
		if !service.WaitForBackgroundTasks(5 * time.Second) {
			t.Errorf("混合意图测试后台任务未完成")
		}
	})

	result, err := service.RunWithOptions(
		ctx,
		"conv-mixed-intent",
		"user-1",
		"assistant-mixed-intent",
		nil,
		RunOptions{AgentMode: agentModeDeep},
	)
	if err != nil {
		t.Fatalf("混合任务运行失败: %v", err)
	}
	if !strings.Contains(result, "项目资产整理完成") ||
		!strings.Contains(result, "指定目标渗透完成") {
		t.Fatalf("混合任务应合并两个阶段结果: %q", result)
	}
	details, err := db.ListProcessDetails(ctx, "conv-mixed-intent", 200)
	if err != nil {
		t.Fatalf("读取过程详情失败: %v", err)
	}
	phaseSeen := false
	for _, detail := range details {
		if detail.EventType == "mission_phase" {
			phaseSeen = true
		}
	}
	if !phaseSeen {
		t.Fatalf("应记录资产阶段到渗透阶段的移交事件")
	}
}

func missionToolNames(t *testing.T, items []tool.BaseTool) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, item := range items {
		info, err := item.Info(context.Background())
		if err != nil {
			t.Fatalf("读取工具定义失败: %v", err)
		}
		if info != nil {
			names[info.Name] = true
		}
	}
	return names
}
