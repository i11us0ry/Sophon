package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/policy"

	"github.com/cloudwego/eino/components/tool"
)

const (
	missionModeAssetInventory = "asset_inventory"
	missionModePentest        = "pentest"
	missionModeMixed          = "mixed"
	missionModeCodeAudit      = "code_audit"
	missionModeCodeValidate   = "code_audit_validate"
	missionModeRetest         = "retest"
	missionModeAppValidation  = "app_validation"
	missionModeProjectWrite   = "project_write"
	missionModeGeneral        = "general"
	missionModeClarify        = "clarify"
	missionModeAgent          = "agent"

	missionPhaseAsset   = "asset"
	missionPhasePentest = "pentest"
	missionPhaseGeneral = "general"

	missionPhaseSourceAudit     = "source_audit"
	missionPhaseRuntimeValidate = "runtime_validate"
	missionPhaseRetest          = "retest_validate"
	missionPhaseAppStatic       = "app_static"
	missionPhaseAppRuntime      = "app_runtime"
	missionPhaseBackendValidate = "backend_validation"

	intentMinConfidence  = 60.0
	intentMaxTargetCount = 50

	boundedFindingMaxSegments  = 2
	boundedFindingMaxToolCalls = 60
	boundedFindingMaxDuration  = 15 * time.Minute
)

var (
	missionSourcePathPattern         = regexp.MustCompile(`(?:^|[[:space:]"'=(])(/[A-Za-z0-9._~@+/-]{2,})`)
	missionRelativeSourcePathPattern = regexp.MustCompile(
		`(?i)(?:^|[[:space:]"'=(])((?:\./)?[A-Za-z0-9._~@+-]+(?:/[A-Za-z0-9._~@+-]+)+\.(?:zip|tar|tgz|gz|bz2|xz|7z|rar|go|js|ts|tsx|jsx|java|py|rb|php|c|h|cc|cpp|hpp|cs|rs|swift|kt|kts|scala|sh|sql|yaml|yml|json|xml|html|htm|aspx|ashx|asmx|config))(?:\b|$)`,
	)
	missionAppArtifactPattern     = regexp.MustCompile(`(?i)(/[A-Za-z0-9._~@+/-]+\.(?:apk|ipa|app))\b`)
	missionVulnerabilityIDPattern = regexp.MustCompile(`(?i)\b(?:vul|vulnerability|finding)[-_][a-z0-9-]{3,}\b|(?:\b[a-f0-9]{16,64}\b)`)
	missionWildcardIPv4Pattern    = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.\*\.\*$`)
)

type missionPlan struct {
	Mode               string   `json:"mode"`
	Tasks              []string `json:"tasks"`
	Stages             []string `json:"stages,omitempty"`
	AssetAction        string   `json:"asset_action,omitempty"`
	SourceRoots        []string `json:"source_roots,omitempty"`
	PentestTargets     []string `json:"pentest_targets,omitempty"`
	VulnerabilityIDs   []string `json:"vulnerability_ids,omitempty"`
	FindingIDs         []string `json:"finding_ids,omitempty"`
	Objective          string   `json:"objective,omitempty"`
	CompletionCriteria string   `json:"completion_criteria,omitempty"`
	AllowFollowUps     bool     `json:"allow_followups,omitempty"`
	MaxSegments        int      `json:"max_segments,omitempty"`
	MaxToolCalls       int      `json:"max_tool_calls,omitempty"`
	Bounded            bool     `json:"bounded,omitempty"`
	RetestAll          bool     `json:"retest_all,omitempty"`
	RetestIDs          []string `json:"retest_ids,omitempty"`
	AppArtifacts       []string `json:"app_artifacts,omitempty"`
	AuthorizationQuote string   `json:"authorization_quote,omitempty"`
	AuthorizedScopes   []string `json:"authorized_scopes,omitempty"`
	ProjectScopeQuote  string   `json:"project_scope_quote,omitempty"`
	ProjectScope       bool     `json:"project_scope,omitempty"`
	WriteTools         []string `json:"write_tools,omitempty"`
	Confidence         float64  `json:"confidence"`
	Reason             string   `json:"reason,omitempty"`
	Source             string   `json:"source,omitempty"`
}

type missionProgressState struct {
	IntentPlan   *missionPlan `json:"intentPlan,omitempty"`
	MissionPhase string       `json:"missionPhase,omitempty"`
}

type missionExecution struct {
	Plan      missionPlan
	Phase     string
	Scope     missionScope
	AgentMode string
}

type missionContextKey struct{}

type missionObjectiveState struct {
	mu        sync.Mutex
	completed bool
	findingID string
	reason    string
}

type missionObjectiveContextKey struct{}

func withMissionExecution(ctx context.Context, execution missionExecution) context.Context {
	return context.WithValue(ctx, missionContextKey{}, execution)
}

func missionExecutionFromContext(ctx context.Context) (missionExecution, bool) {
	value, ok := ctx.Value(missionContextKey{}).(missionExecution)
	return value, ok
}

func withMissionObjectiveState(ctx context.Context) context.Context {
	return context.WithValue(ctx, missionObjectiveContextKey{}, &missionObjectiveState{})
}

func missionObjectiveStateFromContext(ctx context.Context) *missionObjectiveState {
	state, _ := ctx.Value(missionObjectiveContextKey{}).(*missionObjectiveState)
	return state
}

func markMissionObjectiveComplete(ctx context.Context, findingID string, reason string) {
	state := missionObjectiveStateFromContext(ctx)
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.completed {
		return
	}
	state.completed = true
	state.findingID = strings.TrimSpace(findingID)
	state.reason = strings.TrimSpace(reason)
}

func missionObjectiveCompletion(ctx context.Context) (bool, string, string) {
	state := missionObjectiveStateFromContext(ctx)
	if state == nil {
		return false, "", ""
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.completed, state.findingID, state.reason
}

func missionSuppressesAutomaticFollowUps(ctx context.Context) bool {
	if completed, _, _ := missionObjectiveCompletion(ctx); completed {
		return true
	}
	execution, ok := missionExecutionFromContext(ctx)
	return ok && execution.Plan.boundedFindingAudit() && !execution.Plan.AllowFollowUps
}

func (s *Service) markMissionObjectiveCompleteFromFinding(
	ctx context.Context,
	finding *database.Vulnerability,
) {
	execution, ok := missionExecutionFromContext(ctx)
	if !ok || !missionFindingCompletesObjective(execution, finding) {
		return
	}
	markMissionObjectiveComplete(
		ctx,
		finding.ID,
		"漏洞 "+finding.ID+" 已确认可利用并满足当前目标："+finding.Title,
	)
}

func missionFindingCompletesObjective(
	execution missionExecution,
	finding *database.Vulnerability,
) bool {
	if finding == nil ||
		(execution.Plan.Mode != missionModePentest && execution.Plan.Mode != missionModeMixed) ||
		finding.Status != "confirmed" ||
		finding.VerificationState != "exploitable" ||
		finding.Confidence < 80 ||
		(strings.TrimSpace(finding.Evidence) == "" && len(finding.EvidenceRefs) == 0) {
		return false
	}
	if execution.Scope.Active &&
		strings.TrimSpace(finding.AssetID) != "" &&
		!execution.Scope.IncludesAsset(finding.AssetID) {
		return false
	}
	objective := strings.ToLower(strings.TrimSpace(
		execution.Plan.Objective + " " + execution.Plan.CompletionCriteria,
	))
	if !containsAnyText(
		objective,
		"服务器权限", "服务器控制", "完全控制", "远程控制",
		"远程代码执行", "任意命令执行", "获取 shell", "取得 shell",
		"rce",
	) {
		return false
	}
	findingText := strings.ToLower(strings.Join([]string{
		finding.Title,
		finding.VulnerabilityType,
		finding.Impact,
		finding.Evidence,
		finding.Exploitability,
	}, " "))
	return containsAnyText(
		findingText,
		"服务器权限", "服务器控制", "完全控制", "远程控制",
		"远程代码执行", "任意命令", "webshell", "rce",
	) && containsAnyText(
		findingText,
		"命令回显", "命令输出", "whoami", "cmd.exe", "shell",
	)
}

func (plan missionPlan) allowsPentest() bool {
	return (plan.Mode == missionModePentest || plan.Mode == missionModeMixed) &&
		(plan.ProjectScope || len(plan.PentestTargets) > 0 || len(plan.AuthorizedScopes) > 0)
}

func (plan missionPlan) boundedFindingAudit() bool {
	return plan.Bounded ||
		((plan.Mode == missionModeCodeAudit || plan.Mode == missionModeCodeValidate) &&
			len(plan.FindingIDs) > 0)
}

func missionMentionsFindingReference(message string) bool {
	value := strings.ToLower(strings.TrimSpace(message))
	if value == "" {
		return false
	}
	for _, marker := range []string{
		"这个洞", "这个漏洞", "该洞", "该漏洞", "此洞", "此漏洞",
		"上述漏洞", "前述漏洞", "刚才的漏洞", "前面那个漏洞",
		"this finding", "this vulnerability", "that finding", "that vulnerability",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func missionReferencesSpecificFinding(message string) bool {
	if !missionMentionsFindingReference(message) {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(message))
	for _, action := range []string{
		"审计", "验证", "核验", "确认", "看看", "看下", "查", "判断",
		"真的", "真实", "存在", "有效", "误报", "复现", "有问题",
		"audit", "verify", "validate", "check", "real", "exists", "false positive",
	} {
		if strings.Contains(value, action) {
			return true
		}
	}
	return false
}

func missionReferencesExternalFinding(message string) bool {
	value := strings.ToLower(strings.TrimSpace(message))
	if value == "" {
		return false
	}
	return containsAnyText(
		value,
		"其他平台", "另一个平台", "外部平台", "别的平台", "其他工具",
		"外部报告", "厂商报告", "不是复现", "当前已知漏洞",
		"按照它的逻辑", "同样的漏洞", "同类漏洞", "是否存在同样",
		"复现步骤", "请求包", "响应包", "攻击者", "payload", "http/1.1",
		"<target>", "多跳", "攻击链", "外部漏洞", "poc",
		"other platform", "external report", "similar vulnerability",
	)
}

func missionRequiresKnownFindingBinding(message string) bool {
	return missionReferencesSpecificFinding(message) && !missionReferencesExternalFinding(message)
}

func (plan missionPlan) requiresAssetPhase() bool {
	return plan.Mode == missionModeAssetInventory || plan.Mode == missionModeMixed
}

func (plan missionPlan) taskOnly() bool {
	return !plan.allowsPentest()
}

func (plan missionPlan) missionStages() []string {
	if len(plan.Stages) > 0 {
		return append([]string(nil), plan.Stages...)
	}
	switch plan.Mode {
	case missionModeAssetInventory:
		return []string{missionPhaseAsset}
	case missionModeMixed:
		return []string{missionPhaseAsset, missionPhasePentest}
	case missionModePentest:
		return []string{missionPhasePentest}
	case missionModeCodeAudit:
		return []string{missionPhaseSourceAudit}
	case missionModeCodeValidate:
		return []string{missionPhaseSourceAudit, missionPhaseRuntimeValidate}
	case missionModeRetest:
		return []string{missionPhaseRetest}
	case missionModeAppValidation:
		if len(plan.PentestTargets) > 0 {
			return []string{missionPhaseAppStatic, missionPhaseAppRuntime, missionPhaseBackendValidate}
		}
		return []string{missionPhaseAppStatic, missionPhaseAppRuntime}
	default:
		return []string{missionPhaseGeneral}
	}
}

func initialMissionPhase(plan missionPlan) string {
	stages := plan.missionStages()
	if len(stages) == 0 {
		return missionPhaseGeneral
	}
	return stages[0]
}

func normalizeMissionPhase(plan missionPlan, phase string) string {
	phase = strings.ToLower(strings.TrimSpace(phase))
	for _, candidate := range plan.missionStages() {
		if phase == candidate {
			return phase
		}
	}
	return initialMissionPhase(plan)
}

func nextMissionPhase(plan missionPlan, current string) string {
	stages := plan.missionStages()
	for index, stage := range stages {
		if stage == current && index+1 < len(stages) {
			return stages[index+1]
		}
	}
	return ""
}

func missionStageHandoff(plan missionPlan, next string) string {
	switch next {
	case missionPhasePentest:
		return "【阶段移交】资产整理阶段已经完成。现在只执行用户明确指定的渗透目标：" +
			formatMissionTargets(plan) + "。禁止测试其他资产。"
	case missionPhaseRuntimeValidate:
		return "【阶段移交】源码审计阶段已经完成。现在只对明确授权的运行时目标执行最小化漏洞验证：" +
			formatMissionTargets(plan) + "。禁止扩展到生产环境或其他资产。"
	case missionPhaseAppRuntime:
		return "【阶段移交】App 静态分析已经完成。现在只在已授权的设备或模拟器中执行动态验证，" +
			"禁止安装来源不明的更新包或修改非测试数据。"
	case missionPhaseBackendValidate:
		return "【阶段移交】App 动态验证已经完成。现在只验证明确授权的后端目标：" +
			formatMissionTargets(plan) + "。"
	default:
		return "【阶段移交】进入下一执行阶段：" + next + "。只执行该阶段任务，完成后立即结束。"
	}
}

func (s *Service) resolveMissionPlan(
	ctx context.Context,
	conversationID string,
	userID string,
	assistantMessageID string,
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
	message string,
	resumeState *missionProgressState,
	options RunOptions,
) missionPlan {
	if resumeState != nil && resumeState.IntentPlan != nil {
		resumedPlan := *resumeState.IntentPlan
		resumedPlan.Source = "resume"
		resumeMessage := s.missionMessageWithAttachments(ctx, conversationID, message)
		resumedPlan.SourceRoots = mergeMissionSourceRoots(
			resumedPlan.SourceRoots,
			extractMissionSourceRoots(resumeMessage),
		)
		resumedPlan = s.ensureMissionSourceRoots(ctx, userID, project.ID, resumedPlan)
		plan := normalizeMissionPlan(resumedPlan, resumeMessage, project, conversation, assets)
		plan = s.bindMissionFindingReference(ctx, project.ID, userID, resumeMessage, plan)
		if plan.Mode == missionModeClarify {
			return plan
		}
		if plan.Mode != missionModeClarify {
			plan.Source = "resume"
			return plan
		}
	}
	if strings.TrimSpace(options.CampaignID) != "" {
		return missionPlan{
			Mode:         missionModePentest,
			Tasks:        []string{missionModePentest},
			ProjectScope: true,
			Confidence:   100,
			Reason:       "批量任务由 Campaign 显式调度",
			Source:       "campaign",
		}
	}
	if strings.TrimSpace(message) == "" {
		return missionPlan{
			Mode:       missionModeClarify,
			Confidence: 100,
			Reason:     "没有可识别的用户请求",
			Source:     "empty_input",
		}
	}
	if plan, handled := s.retestButtonMissionPlan(
		ctx,
		userID,
		project,
		conversation,
		message,
	); handled {
		return plan
	}
	if plan, handled := s.manualRetestRoleMissionPlan(
		ctx,
		userID,
		project,
		conversation,
		assets,
		message,
	); handled {
		return plan
	}
	message = s.missionMessageWithAttachments(ctx, conversationID, message)
	return directMainAgentPlan(project, conversation, assets, message)
}

func directMainAgentPlan(
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
	message string,
) missionPlan {
	return missionPlan{
		Mode:           missionModeAgent,
		Tasks:          []string{missionModeAgent},
		PentestTargets: explicitMissionTargets(message, conversation, assets),
		ProjectScope:   projectHasStandingAuthorization(project),
		Objective:      strings.TrimSpace(message),
		Confidence:     100,
		Reason:         "由主 Agent 直接理解请求、发现材料并规划执行",
		Source:         "main_agent",
	}
}

func (s *Service) ensureMissionSourceRoots(
	ctx context.Context,
	userID string,
	projectID string,
	plan missionPlan,
) missionPlan {
	if s == nil || s.db == nil ||
		(plan.Mode != missionModeCodeAudit && plan.Mode != missionModeCodeValidate) {
		return plan
	}
	roots, err := s.projectSourceRoots(ctx, projectID, userID)
	if err != nil || len(roots) == 0 {
		return plan
	}
	merged := mergeMissionSourceRoots(plan.SourceRoots, roots)
	if len(merged) == len(plan.SourceRoots) {
		return plan
	}
	plan.SourceRoots = merged
	plan.Reason = strings.TrimSpace(strings.Join([]string{
		plan.Reason,
		"已从当前项目上传附件自动定位源码",
	}, "；"))
	return plan
}

func (s *Service) projectSourceRoots(
	ctx context.Context,
	projectID string,
	userID string,
) ([]string, error) {
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return nil, fmt.Errorf("存储根目录未配置")
	}
	items, err := s.db.ListRecentProjectAttachments(ctx, projectID, userID, 50)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		leftPriority := missionAttachmentPriority(items[i])
		rightPriority := missionAttachmentPriority(items[j])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	roots := make([]string, 0, 10)
	for _, item := range items {
		if missionAttachmentPriority(item) > 1 {
			continue
		}
		path := filepath.Join(root, "chat_uploads", item.StoragePath)
		if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
			continue
		}
		roots = append(roots, path)
		if len(roots) >= 10 {
			break
		}
	}
	return normalizeUniqueStrings(roots), nil
}

func (s *Service) retestButtonMissionPlan(
	ctx context.Context,
	userID string,
	project database.Project,
	conversation database.Conversation,
	message string,
) (missionPlan, bool) {
	if strings.TrimSpace(conversation.Kind) != "retest" ||
		strings.TrimSpace(conversation.AgentRoleID) != SystemRetestAgentID {
		return missionPlan{}, false
	}
	if s == nil || s.db == nil {
		return clarifyMissionPlan("漏洞复测服务不可用"), true
	}
	retestRun, err := s.db.GetRunningVulnerabilityRetestByConversation(
		ctx,
		conversation.ID,
		userID,
	)
	if err != nil || retestRun == nil {
		return clarifyMissionPlan("当前会话未绑定运行中的漏洞复测任务"), true
	}
	vulnerability, err := s.db.GetVulnerability(
		ctx,
		retestRun.VulnerabilityID,
		userID,
	)
	if err != nil || vulnerability == nil || vulnerability.ProjectID != project.ID {
		return clarifyMissionPlan("复测任务关联的漏洞不存在或不属于当前项目"), true
	}
	targets := normalizeMissionTargets(extractMissionHosts(message))
	if len(targets) == 0 {
		return clarifyMissionPlan("复测任务未提供授权目标"), true
	}
	return missionPlan{
		Mode:               missionModeRetest,
		Tasks:              []string{missionModeRetest},
		Stages:             []string{missionPhaseRetest},
		PentestTargets:     targets,
		VulnerabilityIDs:   []string{vulnerability.ID},
		Objective:          "重新验证指定漏洞并提交结构化复测结论",
		CompletionCriteria: "取得本次复测证据，并调用 project_retest_finding 写回结论",
		AllowFollowUps:     false,
		MaxSegments:        boundedFindingMaxSegments,
		MaxToolCalls:       boundedFindingMaxToolCalls,
		Bounded:            true,
		RetestIDs:          []string{retestRun.ID},
		Confidence:         100,
		Reason:             "漏洞复测按钮已绑定运行中的复测任务和授权目标",
		Source:             "retest_button",
	}, true
}

func (s *Service) manualRetestRoleMissionPlan(
	ctx context.Context,
	userID string,
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
	message string,
) (missionPlan, bool) {
	if strings.TrimSpace(conversation.Kind) == "retest" ||
		strings.TrimSpace(conversation.AgentRoleID) != SystemRetestAgentID {
		return missionPlan{}, false
	}
	if s == nil || s.db == nil {
		return clarifyMissionPlan("漏洞复测服务不可用"), true
	}
	candidates := normalizeUniqueStrings(extractMissionVulnerabilityIDs(message))
	validIDs := make([]string, 0, len(candidates))
	for _, findingID := range candidates {
		vulnerability, err := s.db.GetVulnerability(ctx, findingID, userID)
		if err == nil && vulnerability != nil && vulnerability.ProjectID == project.ID {
			validIDs = append(validIDs, vulnerability.ID)
		}
	}
	if len(validIDs) == 0 {
		return clarifyMissionPlan("漏洞复测需要明确提供当前项目中的有效 finding ID"), true
	}
	return missionPlan{
		Mode:               missionModeRetest,
		Tasks:              []string{missionModeRetest},
		Stages:             []string{missionPhaseRetest},
		PentestTargets:     explicitMissionTargets(message, conversation, assets),
		VulnerabilityIDs:   validIDs,
		Objective:          "复测用户指定的当前项目漏洞并提交结构化结论",
		CompletionCriteria: "取得针对性验证证据，并调用 project_retest_finding 写回结论后立即结束",
		AllowFollowUps:     false,
		MaxSegments:        boundedFindingMaxSegments,
		MaxToolCalls:       boundedFindingMaxToolCalls,
		Bounded:            true,
		Confidence:         100,
		Reason:             "当前角色为漏洞复测且消息绑定了当前项目中的有效 finding ID",
		Source:             "retest_role",
	}, true
}

func normalizeMissionPlan(
	plan missionPlan,
	message string,
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
) missionPlan {
	plan.Mode = strings.ToLower(strings.TrimSpace(plan.Mode))
	plan.Reason = strings.TrimSpace(plan.Reason)
	if plan.Confidence > 0 && plan.Confidence <= 1 {
		plan.Confidence *= 100
	}
	if plan.Confidence > 100 {
		plan.Confidence = 100
	}
	if plan.Confidence <= 0 {
		plan.Confidence = 75
	}
	plan = recoverCodeAuditPlanWithSourcePath(plan, message)
	switch plan.Mode {
	case missionModeAssetInventory, missionModePentest, missionModeMixed,
		missionModeCodeAudit, missionModeCodeValidate, missionModeRetest, missionModeAppValidation,
		missionModeProjectWrite, missionModeGeneral, missionModeClarify, missionModeAgent:
	default:
		return clarifyMissionPlan("无法确定请求属于资产整理、渗透测试还是普通任务")
	}
	if plan.Mode == missionModeAgent {
		plan.Tasks = []string{missionModeAgent}
		plan.ProjectScope = projectHasStandingAuthorization(project)
		if strings.TrimSpace(plan.Objective) == "" {
			plan.Objective = strings.TrimSpace(message)
		}
		return plan
	}
	trustedPersistedScope := plan.Source == "resume"
	if plan.Confidence < intentMinConfidence &&
		plan.Mode != missionModeClarify &&
		!missionPlanHasDeterministicInputs(plan, message, project) {
		return clarifyMissionPlan("意图识别置信度不足，请明确任务和测试目标")
	}
	if isExtendedMissionMode(plan.Mode) {
		return normalizeExtendedMissionPlan(
			plan,
			message,
			project,
			conversation,
			assets,
			trustedPersistedScope,
		)
	}
	if plan.Mode == missionModeProjectWrite ||
		plan.Mode == missionModeGeneral ||
		plan.Mode == missionModeClarify {
		if plan.Mode == missionModeClarify && plan.Reason == "" {
			plan.Reason = "需要用户补充明确任务"
		}
		if plan.Mode == missionModeGeneral || plan.Mode == missionModeClarify {
			plan.WriteTools = nil
			plan.PentestTargets = nil
			plan.ProjectScope = false
			plan.AuthorizationQuote = ""
			plan.AuthorizedScopes = nil
			plan.ProjectScopeQuote = ""
		}
		if plan.Mode == missionModeProjectWrite {
			plan.WriteTools = normalizeProjectWriteTools(plan.WriteTools)
			if len(plan.WriteTools) == 0 {
				return clarifyMissionPlan("未识别到可执行的项目写工具")
			}
			plan.Tasks = []string{missionModeProjectWrite}
			plan.PentestTargets = nil
			plan.ProjectScope = false
			plan.AuthorizationQuote = ""
			plan.AuthorizedScopes = nil
			plan.ProjectScopeQuote = ""
		}
		return plan
	}

	if plan.Mode == missionModePentest || plan.Mode == missionModeMixed {
		projectAuthorized := projectHasStandingAuthorization(project)
		authorizationQuote, authorized := validateAuthorizationQuote(message, plan.AuthorizationQuote)
		if !trustedPersistedScope && !projectAuthorized && !authorized {
			return clarifyMissionPlan("未识别到用户本轮明确的外部测试授权")
		}
		if authorized {
			plan.AuthorizationQuote = authorizationQuote
		} else {
			plan.AuthorizationQuote = ""
		}
		plan.AuthorizedScopes = normalizeAuthorizedScopes(message, plan.AuthorizedScopes)
		if len(plan.AuthorizedScopes) > 0 && !authorized {
			return clarifyMissionPlan("本轮新增授权范围缺少用户原文授权引用")
		}
		if plan.ProjectScope && !trustedPersistedScope && !projectAuthorized {
			projectScopeQuote, projectScopeAuthorized := validateAuthorizationQuote(message, plan.ProjectScopeQuote)
			if !projectScopeAuthorized {
				return clarifyMissionPlan("未识别到用户本轮明确的项目级测试授权")
			}
			plan.ProjectScopeQuote = projectScopeQuote
		}
		planTargets := normalizeMissionTargets(plan.PentestTargets)
		explicitTargets := explicitMissionTargets(message, conversation, assets)
		if projectAuthorized && !plan.ProjectScope && len(explicitTargets) == 0 {
			plan.ProjectScope = true
			planTargets = nil
		}
		switch {
		case trustedPersistedScope:
			// 恢复任务沿用已持久化的任务范围，但仍需通过项目授权校验。
		case plan.ProjectScope:
			planTargets = nil
		default:
			if len(planTargets) > 0 && !missionTargetsSubset(planTargets, explicitTargets) {
				return clarifyMissionPlan("任务目标超出了用户本轮明确指定的范围")
			}
			planTargets = explicitTargets
		}
		plan.PentestTargets = normalizeMissionTargets(planTargets)
		if !plan.ProjectScope && len(plan.PentestTargets) == 0 {
			return clarifyMissionPlan("请明确需要渗透测试的域名、IP 或当前会话资产")
		}
		if len(plan.PentestTargets) > intentMaxTargetCount {
			plan.PentestTargets = plan.PentestTargets[:intentMaxTargetCount]
		}
		for _, target := range plan.PentestTargets {
			if !missionTargetAllowed(target, project.Scope) &&
				!targetAllowedByAuthorizedScopes(target, plan.AuthorizedScopes) {
				return clarifyMissionPlan(fmt.Sprintf("目标 %s 不在当前项目授权资产范围内", target))
			}
		}
	}
	switch plan.Mode {
	case missionModeAssetInventory:
		plan.Tasks = []string{missionModeAssetInventory}
		plan.PentestTargets = nil
		plan.ProjectScope = false
		plan.WriteTools = nil
		plan.AuthorizationQuote = ""
		plan.AuthorizedScopes = nil
		plan.ProjectScopeQuote = ""
	case missionModePentest:
		plan.Tasks = []string{missionModePentest}
		plan.WriteTools = nil
	case missionModeMixed:
		plan.Tasks = []string{missionModeAssetInventory, missionModePentest}
		plan.WriteTools = nil
	case missionModeProjectWrite:
		plan.Tasks = []string{missionModeProjectWrite}
	}
	return plan
}

func missionPlanHasDeterministicInputs(
	plan missionPlan,
	message string,
	project database.Project,
) bool {
	sourceInputs := len(plan.SourceRoots) > 0 || len(extractMissionSourceRoots(message)) > 0
	switch plan.Mode {
	case missionModeCodeAudit:
		return sourceInputs
	case missionModeCodeValidate:
		return sourceInputs &&
			(len(plan.PentestTargets) > 0 || projectHasStandingAuthorization(project))
	case missionModeRetest:
		return plan.RetestAll || len(plan.VulnerabilityIDs) > 0
	case missionModeAppValidation:
		return len(plan.AppArtifacts) > 0
	case missionModePentest, missionModeMixed:
		return len(plan.PentestTargets) > 0 ||
			(plan.ProjectScope && projectHasStandingAuthorization(project))
	case missionModeProjectWrite:
		return len(plan.WriteTools) > 0
	default:
		return false
	}
}

func validateAuthorizationQuote(message string, quote string) (string, bool) {
	quote = strings.TrimSpace(quote)
	if quote == "" || len([]rune(quote)) > 500 {
		return "", false
	}
	normalizedMessage := strings.Join(strings.Fields(message), " ")
	normalizedQuote := strings.Join(strings.Fields(quote), " ")
	if len([]rune(normalizedQuote)) < 2 || !strings.Contains(normalizedMessage, normalizedQuote) {
		return "", false
	}
	return quote, true
}

func normalizeAuthorizedScopes(message string, values []string) []string {
	messageLower := strings.ToLower(message)
	scopes := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		raw := strings.TrimSpace(value)
		if raw == "" || !strings.Contains(messageLower, strings.ToLower(raw)) {
			continue
		}
		normalized, ok := normalizeAuthorizedScope(raw)
		if !ok || seen[normalized] {
			continue
		}
		seen[normalized] = true
		scopes = append(scopes, normalized)
	}
	sort.Strings(scopes)
	return scopes
}

func normalizeAuthorizedScope(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", false
	}
	if match := missionWildcardIPv4Pattern.FindStringSubmatch(value); len(match) == 3 {
		first, firstErr := strconv.Atoi(match[1])
		second, secondErr := strconv.Atoi(match[2])
		if firstErr == nil && secondErr == nil &&
			first >= 0 && first <= 255 && second >= 0 && second <= 255 {
			return fmt.Sprintf("%d.%d.0.0/16", first, second), true
		}
		return "", false
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() + "/32", true
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network.String(), true
	}
	if strings.HasPrefix(value, "*.") && len(value) > 2 {
		return value, true
	}
	if !strings.ContainsAny(value, "/ :") && probeHostPattern.FindString(value) == value {
		return value, true
	}
	return "", false
}

func targetAllowedByAuthorizedScopes(target string, scopes []string) bool {
	target = strings.Trim(strings.ToLower(strings.TrimSpace(target)), "[]")
	if target == "" {
		return false
	}
	targetIP := net.ParseIP(target)
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if targetIP != nil {
			if _, network, err := net.ParseCIDR(scope); err == nil && network.Contains(targetIP) {
				return true
			}
			continue
		}
		switch {
		case strings.HasPrefix(scope, "*."):
			suffix := strings.TrimPrefix(scope, "*")
			if strings.HasSuffix(target, suffix) && target != strings.TrimPrefix(suffix, ".") {
				return true
			}
		case target == scope, strings.HasSuffix(target, "."+scope):
			return true
		}
	}
	return false
}

func projectHasStandingAuthorization(project database.Project) bool {
	return strings.EqualFold(strings.TrimSpace(project.Status), "active") &&
		strings.TrimSpace(project.Scope) != ""
}

func normalizeProjectWriteTools(values []string) []string {
	supported := map[string]bool{
		"project_retest_finding":      true,
		"project_verify_finding":      true,
		"project_report_finding":      true,
		"project_update_finding":      true,
		"project_record_fact":         true,
		"project_record_audit":        true,
		"project_link_entities":       true,
		"project_upsert_entity":       true,
		"project_add_intent":          true,
		"project_update_intent":       true,
		"project_sync_graph":          true,
		"project_plan_hypotheses":     true,
		"project_start_hypothesis":    true,
		"project_complete_hypothesis": true,
		"project_record_test":         true,
		"project_insert_assets":       true,
	}
	items := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		name := strings.ToLower(strings.TrimSpace(value))
		if !supported[name] || seen[name] {
			continue
		}
		seen[name] = true
		items = append(items, name)
	}
	sort.Strings(items)
	return items
}

func isExtendedMissionMode(mode string) bool {
	switch mode {
	case missionModeCodeAudit, missionModeCodeValidate, missionModeRetest, missionModeAppValidation:
		return true
	default:
		return false
	}
}

func recoverCodeAuditPlanWithSourcePath(plan missionPlan, message string) missionPlan {
	if plan.Mode != missionModeClarify || missionRequiresKnownFindingBinding(message) {
		return plan
	}
	value := strings.ToLower(message)
	if !containsAnyText(
		value,
		"代码审计", "审计代码", "源码审计", "验证下面的漏洞", "漏洞是否存在",
		"漏洞链是否存在", "确认下面的漏洞", "请确认下面的漏洞", "继续审计",
		"按照它的逻辑", "code audit", "source audit", "verify vulnerability",
	) {
		return plan
	}
	if len(extractMissionSourceRoots(message)) == 0 {
		return plan
	}
	plan.Mode = missionModeCodeAudit
	plan.Confidence = 95
	plan.Reason = "检测到明确源码路径，恢复代码审计"
	return plan
}

func normalizeExtendedMissionPlan(
	plan missionPlan,
	message string,
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
	trustedPersisted bool,
) missionPlan {
	if !trustedPersisted {
		plan.SourceRoots = mergeMissionSourceRoots(
			plan.SourceRoots,
			extractMissionSourceRoots(message),
		)
		plan.VulnerabilityIDs = extractMissionVulnerabilityIDs(message)
		plan.AppArtifacts = extractMissionAppArtifacts(message)
		plan.PentestTargets = explicitMissionTargets(message, conversation, assets)
	}
	plan.SourceRoots = normalizeUniqueStrings(plan.SourceRoots)
	plan.VulnerabilityIDs = normalizeUniqueStrings(plan.VulnerabilityIDs)
	plan.FindingIDs = normalizeUniqueStrings(plan.FindingIDs)
	plan.AppArtifacts = normalizeUniqueStrings(plan.AppArtifacts)
	plan.PentestTargets = normalizeMissionTargets(plan.PentestTargets)
	plan.ProjectScope = false
	plan.WriteTools = nil
	requestedStages := normalizeUniqueStrings(plan.Stages)
	projectAuthorized := projectHasStandingAuthorization(project)
	if !trustedPersisted && !projectAuthorized &&
		(plan.Mode == missionModeCodeValidate || plan.Mode == missionModeRetest) {
		authorizationQuote, authorized := validateAuthorizationQuote(message, plan.AuthorizationQuote)
		if !authorized {
			return clarifyMissionPlan("当前任务包含运行时验证，需要用户本轮明确授权")
		}
		plan.AuthorizationQuote = authorizationQuote
	}

	switch plan.Mode {
	case missionModeCodeAudit:
		if len(plan.SourceRoots) == 0 {
			return clarifyMissionPlan("代码审计需要明确提供源码目录路径")
		}
		plan.Tasks = []string{missionModeCodeAudit}
		plan.Stages = []string{missionPhaseSourceAudit}
	case missionModeCodeValidate:
		if len(plan.SourceRoots) == 0 {
			return clarifyMissionPlan("代码审计加漏洞验证需要明确提供源码目录路径")
		}
		if len(plan.PentestTargets) == 0 && projectHasStandingAuthorization(project) {
			plan.PentestTargets = normalizeMissionTargets(extractMissionHosts(project.Scope))
		}
		if len(plan.PentestTargets) == 0 {
			return clarifyMissionPlan("代码审计加漏洞验证需要明确提供运行时验证目标")
		}
		for _, target := range plan.PentestTargets {
			if !missionTargetAllowed(target, project.Scope) {
				return clarifyMissionPlan(fmt.Sprintf("运行时目标 %s 不在项目授权范围内", target))
			}
		}
		plan.Tasks = []string{missionModeCodeAudit, missionModePentest}
		plan.Stages = []string{missionPhaseSourceAudit, missionPhaseRuntimeValidate}
	case missionModeRetest:
		if !plan.RetestAll && len(plan.VulnerabilityIDs) == 0 {
			return clarifyMissionPlan("漏洞复测需要明确提供漏洞 ID")
		}
		plan.Tasks = []string{missionModeRetest}
		plan.Stages = []string{missionPhaseRetest}
	case missionModeAppValidation:
		if len(plan.AppArtifacts) == 0 {
			return clarifyMissionPlan("App 验证需要明确提供 APK、IPA 或 App 包路径")
		}
		for _, target := range plan.PentestTargets {
			if !missionTargetAllowed(target, project.Scope) {
				return clarifyMissionPlan(fmt.Sprintf("App 后端验证目标 %s 不在项目授权范围内", target))
			}
		}
		plan.Tasks = []string{missionModeAppValidation}
		plan.Stages = normalizeAppValidationStages(requestedStages, len(plan.PentestTargets) > 0)
		requiresRuntimeAuthorization := false
		for _, stage := range plan.Stages {
			if stage == missionPhaseBackendValidate && len(plan.PentestTargets) == 0 {
				return clarifyMissionPlan("App 后端验证需要明确提供授权后端目标")
			}
			if stage == missionPhaseAppRuntime || stage == missionPhaseBackendValidate {
				requiresRuntimeAuthorization = true
			}
		}
		if !trustedPersisted && requiresRuntimeAuthorization && !projectAuthorized {
			authorizationQuote, authorized := validateAuthorizationQuote(message, plan.AuthorizationQuote)
			if !authorized {
				return clarifyMissionPlan("App 动态或后端验证需要用户本轮明确授权")
			}
			plan.AuthorizationQuote = authorizationQuote
		}
	}
	return plan
}

func normalizeAppValidationStages(stages []string, hasTargets bool) []string {
	wantRuntime := false
	wantBackend := false
	for _, stage := range stages {
		switch stage {
		case missionPhaseAppRuntime:
			wantRuntime = true
		case missionPhaseBackendValidate:
			wantRuntime = true
			wantBackend = true
		}
	}
	if hasTargets {
		wantRuntime = true
		wantBackend = true
	}
	result := []string{missionPhaseAppStatic}
	if wantRuntime {
		result = append(result, missionPhaseAppRuntime)
	}
	if wantBackend {
		result = append(result, missionPhaseBackendValidate)
	}
	return result
}

func normalizeUniqueStrings(values []string) []string {
	seen := map[string]bool{}
	items := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func (s *Service) hydrateMissionPlan(
	ctx context.Context,
	conversationID string,
	projectID string,
	userID string,
	assets []database.Asset,
	plan missionPlan,
) missionPlan {
	if plan.Mode != missionModeRetest || s == nil || s.db == nil {
		return plan
	}
	if len(plan.RetestIDs) > 0 {
		return plan
	}
	if plan.RetestAll {
		items, total, err := s.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
			OwnerUserID: userID,
			ProjectID:   projectID,
			Limit:       1000,
		})
		if err != nil {
			return clarifyMissionPlan("无法读取当前项目漏洞清单：" + err.Error())
		}
		if len(items) == 0 {
			return clarifyMissionPlan("当前项目没有可复测漏洞")
		}
		plan.VulnerabilityIDs = plan.VulnerabilityIDs[:0]
		for _, item := range items {
			plan.VulnerabilityIDs = append(plan.VulnerabilityIDs, item.ID)
		}
		plan.Reason = strings.TrimSpace(strings.Join([]string{
			plan.Reason,
			fmt.Sprintf("项目共有 %d 条漏洞，本轮批量处理 %d 条", total, len(items)),
		}, "；"))
	}
	plan.VulnerabilityIDs = normalizeUniqueStrings(plan.VulnerabilityIDs)
	if len(plan.VulnerabilityIDs) == 0 {
		return clarifyMissionPlan("漏洞复测需要明确提供漏洞 ID")
	}

	explicitTargets := append([]string(nil), plan.PentestTargets...)
	targets := append([]string(nil), explicitTargets...)
	allowExplicitTargetFallback := !plan.RetestAll && len(plan.VulnerabilityIDs) == 1
	retestableIDs := make([]string, 0, len(plan.VulnerabilityIDs))
	for _, vulnerabilityID := range plan.VulnerabilityIDs {
		vulnerability, err := s.db.GetVulnerability(ctx, vulnerabilityID, userID)
		if err != nil || vulnerability == nil || vulnerability.ProjectID != projectID {
			if plan.RetestAll {
				continue
			}
			return clarifyMissionPlan("漏洞 " + vulnerabilityID + " 不存在或不属于当前项目")
		}
		vulnerabilityTargets := extractMissionHosts(vulnerability.Target)
		if len(vulnerabilityTargets) == 0 {
			for _, asset := range assets {
				if asset.ID == vulnerability.AssetID {
					vulnerabilityTargets = extractMissionHosts(asset.Value + " " + asset.Name)
					break
				}
			}
		}
		if len(vulnerabilityTargets) == 0 && allowExplicitTargetFallback {
			vulnerabilityTargets = append(vulnerabilityTargets, explicitTargets...)
		}
		if len(vulnerabilityTargets) == 0 {
			if plan.RetestAll {
				continue
			}
			return clarifyMissionPlan("原漏洞没有可用于复测的资产或目标地址")
		}
		retestableIDs = append(retestableIDs, vulnerabilityID)
		targets = append(targets, vulnerabilityTargets...)
	}
	plan.VulnerabilityIDs = normalizeUniqueStrings(retestableIDs)
	plan.PentestTargets = normalizeMissionTargets(targets)
	if len(plan.VulnerabilityIDs) == 0 || len(plan.PentestTargets) == 0 {
		return clarifyMissionPlan("原漏洞没有可用于复测的资产或目标地址")
	}
	for _, vulnerabilityID := range plan.VulnerabilityIDs {
		retestRun, err := s.db.CreateVulnerabilityRetestRun(
			ctx,
			vulnerabilityID,
			userID,
			conversationID,
			nil,
		)
		if err != nil {
			if plan.RetestAll {
				continue
			}
			return clarifyMissionPlan("无法创建漏洞复测任务：" + err.Error())
		}
		plan.RetestIDs = append(plan.RetestIDs, retestRun.ID)
	}
	if len(plan.RetestIDs) == 0 {
		return clarifyMissionPlan("当前没有可创建复测任务的漏洞")
	}
	return plan
}

func (s *Service) bindMissionFindingReference(
	ctx context.Context,
	projectID string,
	userID string,
	message string,
	plan missionPlan,
) missionPlan {
	referenceRequired := missionRequiresKnownFindingBinding(message)
	if plan.Mode != missionModeCodeAudit && plan.Mode != missionModeCodeValidate {
		if plan.Mode == missionModeRetest {
			return plan
		}
		if referenceRequired {
			return clarifyMissionPlan("该请求引用了一个已有漏洞，但未形成可审计的具体任务；请明确漏洞标题或 ID 以及要核验的问题")
		}
		return plan
	}
	candidates := append([]string(nil), plan.FindingIDs...)
	if len(candidates) == 0 && len(plan.VulnerabilityIDs) > 0 {
		candidates = append(candidates, plan.VulnerabilityIDs...)
	}
	if len(candidates) == 0 {
		if referenceRequired {
			return clarifyMissionPlan("无法唯一确定“这个洞”指向哪条已记录漏洞，请提供漏洞标题或 ID")
		}
		return plan
	}
	if s == nil || s.db == nil {
		return clarifyMissionPlan("无法校验已有漏洞引用")
	}

	valid := make([]string, 0, len(candidates))
	title := ""
	for _, findingID := range normalizeUniqueStrings(candidates) {
		item, err := s.db.GetVulnerability(ctx, findingID, userID)
		if err != nil || item == nil || item.ProjectID != projectID {
			continue
		}
		valid = append(valid, findingID)
		if title == "" {
			title = item.Title
		}
	}
	if len(valid) == 0 {
		if referenceRequired {
			return clarifyMissionPlan("指定的漏洞没有匹配到当前项目中的有效记录，请提供漏洞标题或 ID")
		}
		plan.FindingIDs = nil
		plan.VulnerabilityIDs = nil
		plan.Bounded = false
		return plan
	}
	if referenceRequired && len(valid) > 1 {
		return clarifyMissionPlan("“这个洞”匹配到多条漏洞，请明确要核验的漏洞 ID")
	}

	plan.FindingIDs = normalizeUniqueStrings(valid)
	plan.Bounded = true
	plan.AllowFollowUps = false
	plan.MaxSegments = boundedLimit(plan.MaxSegments, boundedFindingMaxSegments)
	plan.MaxToolCalls = boundedLimit(plan.MaxToolCalls, boundedFindingMaxToolCalls)
	if strings.TrimSpace(plan.Objective) == "" {
		plan.Objective = "核验已记录漏洞 " + plan.FindingIDs[0] + " 是否真实存在"
		if strings.TrimSpace(title) != "" {
			plan.Objective += "：" + title
		}
	}
	if strings.TrimSpace(plan.CompletionCriteria) == "" {
		plan.CompletionCriteria = "只针对指定漏洞给出 confirmed、refuted 或 insufficient_evidence，并附最小充分证据"
	}
	plan.Reason = strings.TrimSpace(strings.Join([]string{
		plan.Reason,
		"已绑定单条已有漏洞，本轮是有界真实性核验，不自动扩展后续意图",
	}, "；"))
	return plan
}

func boundedLimit(value int, maximum int) int {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

func (s *Service) validateMissionVulnerabilityIDs(
	ctx context.Context,
	projectID string,
	userID string,
	plan missionPlan,
) missionPlan {
	if s == nil || s.db == nil || len(plan.VulnerabilityIDs) == 0 {
		return plan
	}
	valid := make([]string, 0, len(plan.VulnerabilityIDs))
	for _, vulnerabilityID := range plan.VulnerabilityIDs {
		vulnerability, err := s.db.GetVulnerability(ctx, vulnerabilityID, userID)
		if err != nil || vulnerability == nil || vulnerability.ProjectID != projectID {
			continue
		}
		valid = append(valid, vulnerabilityID)
	}
	plan.VulnerabilityIDs = normalizeUniqueStrings(valid)
	if plan.Mode == missionModeRetest && !plan.RetestAll && len(plan.VulnerabilityIDs) == 0 {
		return clarifyMissionPlan("漏洞复测需要明确且属于当前项目的漏洞 ID")
	}
	return plan
}

func (s *Service) validateMissionInputPaths(ctx context.Context, conversationID string, plan missionPlan) missionPlan {
	if s == nil {
		return plan
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		if len(plan.SourceRoots) > 0 || len(plan.AppArtifacts) > 0 {
			return clarifyMissionPlan("当前存储根目录未配置，无法校验源码或 App 路径")
		}
		return plan
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return clarifyMissionPlan("无法解析存储根目录")
	}
	workspace := filepath.Join(root, "tmp", "workspace", strings.TrimSpace(conversationID))
	uploads := filepath.Join(root, "chat_uploads")
	attachmentPaths := map[string]bool{}
	if s.db != nil {
		if items, err := s.db.ListAttachments(ctx, conversationID); err == nil {
			for _, item := range items {
				attachmentPaths[filepath.Clean(filepath.Join(uploads, item.StoragePath))] = true
			}
		}
	}
	within := func(base string, absolute string) bool {
		if resolved, err := filepath.EvalSymlinks(base); err == nil {
			base = resolved
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		rel, err := filepath.Rel(base, absolute)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
	}
	validate := func(raw string, wantDir bool, allowedRoots []string) (string, error) {
		path := strings.TrimSpace(raw)
		if path == "" {
			return "", fmt.Errorf("路径为空")
		}
		if !filepath.IsAbs(path) {
			candidates := []string{
				filepath.Join(workspace, path),
				filepath.Join(uploads, path),
			}
			path = candidates[0]
			for _, candidate := range candidates {
				if _, statErr := os.Stat(candidate); statErr == nil {
					path = candidate
					break
				}
			}
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
			absolute = resolved
		}
		allowed := false
		for _, allowedRoot := range allowedRoots {
			if within(allowedRoot, absolute) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("路径不在当前会话工作区或上传目录")
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return "", err
		}
		if wantDir && !info.IsDir() && !missionSourceArchiveOrFile(absolute) {
			return "", fmt.Errorf("源码路径不是目录或源码文件")
		}
		if !wantDir && !info.Mode().IsRegular() {
			return "", fmt.Errorf("App 包路径不是文件")
		}
		if !info.IsDir() && within(uploads, absolute) && !attachmentPaths[absolute] {
			if !s.missionProjectUploadAllowed(ctx, conversationID, uploads, absolute) {
				return "", fmt.Errorf("文件不属于当前项目上传范围")
			}
		}
		return absolute, nil
	}
	resolvedSources := make([]string, 0, len(plan.SourceRoots))
	var sourceErr error
	for _, sourceRoot := range plan.SourceRoots {
		resolved, err := validate(sourceRoot, true, []string{workspace, uploads})
		if err != nil {
			if sourceErr == nil {
				sourceErr = err
			}
			continue
		}
		resolvedSources = append(resolvedSources, resolved)
	}
	if len(plan.SourceRoots) > 0 && len(resolvedSources) == 0 {
		return clarifyMissionPlan("源码路径不可用：" + sourceErr.Error())
	}
	plan.SourceRoots = normalizeUniqueStrings(resolvedSources)
	resolvedArtifacts := make([]string, 0, len(plan.AppArtifacts))
	var artifactErr error
	for _, appArtifact := range plan.AppArtifacts {
		resolved, err := validate(appArtifact, false, []string{workspace, uploads})
		if err != nil {
			if artifactErr == nil {
				artifactErr = err
			}
			continue
		}
		resolvedArtifacts = append(resolvedArtifacts, resolved)
	}
	if len(plan.AppArtifacts) > 0 && len(resolvedArtifacts) == 0 {
		return clarifyMissionPlan("App 包路径不可用：" + artifactErr.Error())
	}
	plan.AppArtifacts = normalizeUniqueStrings(resolvedArtifacts)
	return plan
}

func (s *Service) missionProjectUploadAllowed(
	ctx context.Context,
	currentConversationID string,
	uploads string,
	absolute string,
) bool {
	if s == nil || s.db == nil || currentConversationID == "" {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(uploads); err == nil {
		uploads = resolved
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	relative, err := filepath.Rel(uploads, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) < 2 {
		return false
	}
	targetConversationID := strings.TrimSpace(parts[0])
	if targetConversationID == "" || targetConversationID == currentConversationID {
		return false
	}
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if userID == "" {
		return false
	}
	current, err := s.db.GetConversation(ctx, currentConversationID, userID)
	if err != nil || current == nil || strings.TrimSpace(current.ProjectID) == "" {
		return false
	}
	target, err := s.db.GetConversation(ctx, targetConversationID, userID)
	if err != nil || target == nil || target.ProjectID != current.ProjectID {
		return false
	}
	return true
}

func missionSourceArchiveOrFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".go", ".js", ".ts", ".tsx", ".jsx", ".java", ".py", ".rb", ".php",
		".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".kt",
		".kts", ".scala", ".sh", ".sql", ".yaml", ".yml", ".json", ".xml",
		".txt", ".md":
		return true
	default:
		return false
	}
}

func clarifyMissionPlan(reason string) missionPlan {
	return missionPlan{
		Mode:       missionModeClarify,
		Tasks:      nil,
		Confidence: 100,
		Reason:     strings.TrimSpace(reason),
	}
}

func normalizeMissionTargets(values []string) []string {
	seen := map[string]bool{}
	items := make([]string, 0, len(values))
	for _, value := range values {
		target := normalizeMissionTarget(value)
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		items = append(items, target)
	}
	sort.Strings(items)
	return items
}

func normalizeMissionTarget(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "<>\"'")
	if value == "" {
		return ""
	}
	if !strings.Contains(value, "://") {
		value = "https://" + strings.TrimPrefix(value, "//")
	}
	parsed, err := url.Parse(value)
	if err != nil || strings.TrimSpace(parsed.Hostname()) == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
}

func missionTargetAllowed(target string, projectScope string) bool {
	target = normalizeMissionTarget(target)
	if target == "" {
		return false
	}
	if net.ParseIP(target) != nil {
		for _, pattern := range missionScopePatterns(projectScope) {
			if _, network, err := net.ParseCIDR(pattern); err == nil && network.Contains(net.ParseIP(target)) {
				return true
			}
			if strings.EqualFold(pattern, target) {
				return true
			}
		}
	}
	for _, pattern := range missionScopePatterns(projectScope) {
		if missionHostPatternAllows(pattern, target) {
			return true
		}
	}
	return false
}

func missionScopePatterns(projectScope string) []string {
	values := make([]string, 0, 8)
	replacer := strings.NewReplacer("，", " ", ",", " ", "；", " ", ";", " ", "\n", " ", "\t", " ")
	for _, item := range strings.Fields(replacer.Replace(projectScope)) {
		item = strings.TrimSpace(strings.Trim(item, "[](){}<>"))
		if item == "" || strings.Contains(item, "授权") || strings.Contains(item, "scope") {
			continue
		}
		values = append(values, item)
	}
	return normalizeMissionPatterns(values)
}

func normalizeMissionPatterns(values []string) []string {
	seen := map[string]bool{}
	items := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if strings.HasPrefix(value, "*") && !strings.HasPrefix(value, "*.") {
			value = "*." + strings.TrimPrefix(value, "*")
		}
		if !strings.Contains(value, "://") && !strings.HasPrefix(value, "*.") {
			if parsed, err := url.Parse("https://" + value); err == nil && parsed.Hostname() != "" {
				value = parsed.Hostname()
			}
		} else if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			value = parsed.Hostname()
		}
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = strings.Trim(host, "[]")
		}
		value = strings.TrimSuffix(strings.TrimSpace(value), ".")
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		items = append(items, value)
	}
	sort.Strings(items)
	return items
}

func missionHostPatternAllows(pattern, target string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	target = strings.ToLower(strings.TrimSpace(target))
	if pattern == "" || target == "" {
		return false
	}
	if pattern == target {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(target, suffix) && len(target) > len(suffix)
	}
	if strings.Contains(pattern, ".") {
		return strings.HasSuffix(target, "."+pattern)
	}
	return false
}

func containsAnyText(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func explicitMissionTargets(
	message string,
	conversation database.Conversation,
	assets []database.Asset,
) []string {
	targets := normalizeMissionTargets(extractMissionHosts(message))
	if len(targets) > 0 || strings.TrimSpace(conversation.AssetID) == "" {
		return targets
	}
	for _, asset := range assets {
		if asset.ID == strings.TrimSpace(conversation.AssetID) {
			return normalizeMissionTargets(extractMissionHosts(asset.Value + " " + asset.Name))
		}
	}
	return nil
}

func missionTargetsSubset(candidates []string, allowed []string) bool {
	if len(candidates) == 0 {
		return true
	}
	allowedSet := map[string]bool{}
	for _, item := range normalizeMissionTargets(allowed) {
		allowedSet[item] = true
	}
	for _, item := range normalizeMissionTargets(candidates) {
		if !allowedSet[item] {
			return false
		}
	}
	return true
}

func extractMissionSourceRoots(message string) []string {
	matches := missionSourcePathPattern.FindAllStringSubmatch(message, -1)
	matches = append(
		matches,
		missionRelativeSourcePathPattern.FindAllStringSubmatch(message, -1)...,
	)
	filtered := make([][]string, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 2 && missionSourcePathCandidate(match[1]) {
			filtered = append(filtered, match)
		}
	}
	return normalizeMissionPaths(filtered)
}

func mergeMissionSourceRoots(primary, extracted []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(primary)+len(extracted))
	for _, value := range append(append([]string(nil), primary...), extracted...) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func missionSourcePathCandidate(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(path)))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf", ".doc", ".docx",
		".xls", ".xlsx", ".ppt", ".pptx", ".apk", ".ipa", ".app":
		return false
	default:
		return true
	}
}

func (s *Service) missionMessageWithAttachments(
	ctx context.Context,
	conversationID string,
	message string,
) string {
	if s == nil || s.db == nil || strings.TrimSpace(conversationID) == "" {
		return message
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return message
	}
	userID := strings.TrimSpace(execctx.UserID(ctx))
	items, err := s.db.ListRecentAttachments(ctx, conversationID, 10)
	label := "[本轮会话附件]"
	if userID != "" {
		if conversation, loadErr := s.db.GetConversation(ctx, conversationID, userID); loadErr == nil &&
			conversation != nil && strings.TrimSpace(conversation.ProjectID) != "" {
			if projectItems, projectErr := s.db.ListRecentProjectAttachments(
				ctx,
				conversation.ProjectID,
				userID,
				50,
			); projectErr == nil {
				items = projectItems
				label = "[本项目最近附件]"
				err = nil
			}
		}
	}
	if err != nil || len(items) == 0 {
		return message
	}
	sort.SliceStable(items, func(i, j int) bool {
		leftPriority := missionAttachmentPriority(items[i])
		rightPriority := missionAttachmentPriority(items[j])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > 10 {
		items = items[:10]
	}
	var builder strings.Builder
	builder.WriteString(message)
	builder.WriteString("\n\n")
	builder.WriteString(label)
	for _, item := range items {
		builder.WriteString("\n- name=")
		builder.WriteString(item.FileName)
		builder.WriteString(" path=")
		builder.WriteString(filepath.Join(root, "chat_uploads", item.StoragePath))
	}
	return builder.String()
}

func missionAttachmentPriority(item database.Attachment) int {
	ext := strings.ToLower(filepath.Ext(strings.TrimSpace(item.FileName)))
	switch ext {
	case ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar":
		return 0
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".java", ".py", ".rb", ".php",
		".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".kt", ".kts",
		".scala", ".sh", ".sql", ".yaml", ".yml", ".json", ".xml", ".html", ".htm",
		".aspx", ".ashx", ".asmx", ".config", ".sln", ".csproj":
		return 1
	default:
		return 2
	}
}

func extractMissionAppArtifacts(message string) []string {
	return normalizeMissionPaths(missionAppArtifactPattern.FindAllStringSubmatch(message, -1))
}

func normalizeMissionPaths(matches [][]string) []string {
	seen := map[string]bool{}
	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		path := strings.TrimSpace(match[1])
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func extractMissionVulnerabilityIDs(message string) []string {
	seen := map[string]bool{}
	ids := make([]string, 0)
	for _, id := range missionVulnerabilityIDPattern.FindAllString(message, -1) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func missionScopeFromPlan(
	ctx context.Context,
	plan missionPlan,
	assets []database.Asset,
) missionScope {
	scope := missionScope{}
	if plan.ProjectScope {
		return scope
	}
	scope.AuthorizedScopes = append([]string(nil), plan.AuthorizedScopes...)
	hosts := make([]string, 0, len(plan.PentestTargets)+1)
	hosts = append(hosts, plan.PentestTargets...)
	if len(hosts) == 0 && strings.TrimSpace(execctx.AssetID(ctx)) != "" {
		for _, asset := range assets {
			if asset.ID == strings.TrimSpace(execctx.AssetID(ctx)) {
				hosts = append(hosts, extractMissionHosts(asset.Value+" "+asset.Name)...)
				break
			}
		}
	}
	scope.Hosts = normalizeMissionTargets(hosts)
	if len(scope.Hosts) == 0 && len(scope.AuthorizedScopes) == 0 {
		return scope
	}
	scope.Active = true
	for _, asset := range assets {
		assetHosts := extractMissionHosts(asset.Value + " " + asset.Name)
		matched := false
		for _, host := range scope.Hosts {
			for _, assetHost := range assetHosts {
				if strings.EqualFold(assetHost, host) {
					scope.AssetIDs = append(scope.AssetIDs, asset.ID)
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
	}
	assetSet := map[string]bool{}
	for _, assetID := range scope.AssetIDs {
		if strings.TrimSpace(assetID) != "" {
			assetSet[assetID] = true
		}
	}
	scope.AssetIDs = limitedSortedKeys(assetSet, 0)
	return scope
}

func parseMissionProgressState(raw string) (*missionProgressState, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var state missionProgressState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, err
	}
	if state.IntentPlan == nil {
		return nil, nil
	}
	return &state, nil
}

func missionProgressPayload(plan missionPlan, phase string, values map[string]interface{}) map[string]interface{} {
	payload := make(map[string]interface{}, len(values)+2)
	for key, value := range values {
		payload[key] = value
	}
	payload["intentPlan"] = plan
	payload["missionPhase"] = phase
	return payload
}

func missionPlanGuidance(plan missionPlan, phase string) string {
	var builder strings.Builder
	builder.WriteString("\n\n【服务端任务意图边界】\n")
	builder.WriteString("意图模式：" + plan.Mode + "；执行阶段：" + phase + "。\n")
	switch plan.Mode {
	case missionModeAgent:
		builder.WriteString("由你直接理解并执行用户请求。缺少历史上下文或材料位置时，主动调用 search_project_history 或 discover_project_sources；" +
			"不要要求用户重复提供已经上传的项目源码路径。执行仍受项目授权范围和工具策略约束。\n")
	case missionModeAssetInventory:
		builder.WriteString("本轮只允许读取和分析当前项目内的资产、事实、漏洞、测试覆盖和攻击路径，给出资产整理结果与继续测试优先级。" +
			"禁止发起网络探测、漏洞扫描、渗透测试或调用子 Agent；完成分析后立即结束。\n")
	case missionModeGeneral:
		builder.WriteString("本轮只处理用户要求的普通项目任务。禁止把任务扩展成渗透测试，禁止调用网络扫描和子 Agent；完成回答后立即结束。\n")
	case missionModeCodeAudit:
		if plan.boundedFindingAudit() {
			builder.WriteString("本轮只核验已有漏洞 " + strings.Join(plan.FindingIDs, "、") +
				" 是否真实存在。目标：" + plan.Objective + "；完成条件：" + plan.CompletionCriteria +
				"。不得扩展到其他漏洞、其他入口或自动派生后续意图；证据足够后立即给出 confirmed、refuted 或 insufficient_evidence 结论并停止。\n")
		} else {
			builder.WriteString("本轮优先审计用户明确提供的源码目录或源码包。源码包必须先解压到当前会话工作区；网络请求仅允许访问活动项目授权范围内的目标；只生成带文件、行号和数据流证据的候选结论。\n")
		}
	case missionModeCodeValidate:
		if phase == missionPhaseSourceAudit {
			builder.WriteString("当前优先执行源码审计。网络请求仅允许访问活动项目授权范围内的目标；先形成候选问题、复现条件和目标映射。\n")
		} else {
			builder.WriteString("源码审计已完成。现在只验证已映射到明确授权运行时目标的候选漏洞：" +
				formatMissionTargets(plan) + "。没有运行时证据不得标记 confirmed。\n")
		}
	case missionModeRetest:
		builder.WriteString("本轮只复测明确指定的漏洞：" + strings.Join(plan.VulnerabilityIDs, "、") +
			"；复测任务 ID：" + strings.Join(plan.RetestIDs, "、") +
			"。只重放原漏洞最小 PoC，不探索其他漏洞或资产；结束时必须调用 project_retest_finding。\n")
	case missionModeAppValidation:
		switch phase {
		case missionPhaseAppStatic:
			builder.WriteString("当前优先对用户提供的 App 包执行静态分析；网络请求仅允许访问活动项目授权范围内的目标。\n")
		case missionPhaseAppRuntime:
			builder.WriteString("当前只执行 App 动态运行验证，必须使用指定包和测试设备/模拟器，不得修改非测试数据。\n")
		case missionPhaseBackendValidate:
			builder.WriteString("当前只验证 App 对应的明确授权后端目标：" + formatMissionTargets(plan) + "。\n")
		}
	case missionModeProjectWrite:
		builder.WriteString("本轮只执行用户明确要求的项目数据修改。允许使用项目写工具，但禁止网络探测、渗透测试和子 Agent；完成后立即结束。\n")
	case missionModeClarify:
		builder.WriteString("用户意图或测试范围不明确。不得执行工具，只要求用户补充明确任务和授权目标。\n")
	case missionModePentest:
		builder.WriteString("本轮只执行用户明确授权的渗透任务。测试目标：" + formatMissionTargets(plan) + "。禁止扩展到其他资产。\n")
	case missionModeMixed:
		if phase == missionPhaseAsset {
			builder.WriteString("当前只执行资产整理阶段。禁止网络探测和渗透测试；资产整理完成后由平台移交给渗透阶段。\n")
		} else {
			builder.WriteString("资产阶段已完成。现在只渗透用户明确指定的目标：" + formatMissionTargets(plan) + "。禁止测试其他资产。\n")
		}
	}
	builder.WriteString("完成任务后停止，不得因为项目中还存在其他未测试资产而自行继续。\n")
	return builder.String()
}

func formatMissionTargets(plan missionPlan) string {
	if plan.ProjectScope {
		if len(plan.AuthorizedScopes) > 0 {
			return "整个项目授权范围 + " + strings.Join(plan.AuthorizedScopes, "、")
		}
		return "整个项目授权范围"
	}
	if len(plan.PentestTargets) == 0 {
		if len(plan.AuthorizedScopes) > 0 {
			return strings.Join(plan.AuthorizedScopes, "、")
		}
		return "未指定"
	}
	return strings.Join(plan.PentestTargets, "、")
}

func agentInstructionForMission(mode string, plan missionPlan, phase string) string {
	instruction := agentInstructionForMode(mode) + missionPlanGuidance(plan, phase)
	if normalizeAgentMode(mode) == agentModeDeep && phase == missionPhasePentest && plan.allowsPentest() {
		instruction += "\nDeep Path 阶段要求：必须通过 pent_agent_execute 把渗透任务交给受限子 Agent，" +
			"task 参数中完整包含本轮明确目标和完成条件；主 Agent 不得自行扩展到目标列表之外的资产。"
	}
	if normalizeAgentMode(mode) == agentModeDeep &&
		plan.Mode == missionModeCodeAudit &&
		phase == missionPhaseSourceAudit {
		instruction += "\n代码审计多 Agent 职责边界：" +
			"主 Agent 只负责项目协调、规划调度和结果汇总，必须先调用 pent_agent_plan_hypotheses，" +
			"再使用 project_list_hypotheses 获取工作单元，并逐个调用 pent_agent_execute_hypothesis。" +
			"主 Agent 无权直接调用 exec、execute-python-script、read_skill 或通用 pent_agent_execute；" +
			"源码解压、索引、扫描、IL 分析和漏洞取证全部由 Worker 完成。"
	}
	return instruction
}

func (s *Service) mainAgentInstruction(ctx context.Context) string {
	instruction := defaultSystemPrompt
	if execution, ok := missionExecutionFromContext(ctx); ok {
		instruction = agentInstructionForMission(
			execution.AgentMode,
			execution.Plan,
			execution.Phase,
		)
	}
	if policyPrompt := s.systemAgentPrompt(
		ctx,
		SystemMissionPolicyAgentID,
		SystemMissionPolicyAgentName,
		missionPolicyAgentPrompt,
	); strings.TrimSpace(policyPrompt) != "" {
		instruction += "\n\n" + policyPrompt
	}
	return withPlatformVerificationWorkflow(instruction)
}

func (s *Service) missionSourceAccessGuidance(ctx context.Context) string {
	execution, ok := missionExecutionFromContext(ctx)
	if !ok || len(execution.Plan.SourceRoots) == 0 {
		return ""
	}
	if execution.Phase != missionPhaseSourceAudit && execution.Phase != missionPhaseAppStatic {
		return ""
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if root == "" || conversationID == "" {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("\n\n源码输入访问规则：")
	builder.WriteString("可直接读取同一用户、同一项目下所有对话的上传文件；禁止读取其他项目、其他用户、/opt/sophon 根目录、父目录或非授权系统路径。\n")
	builder.WriteString("- 当前项目公共上传目录：")
	builder.WriteString(filepath.Join(root, "chat_uploads"))
	builder.WriteString("\n- 当前会话上传目录：")
	builder.WriteString(filepath.Join(root, "chat_uploads", conversationID))
	builder.WriteString("\n- 工作区：")
	builder.WriteString(filepath.Join(root, "tmp", "workspace", conversationID))
	builder.WriteString("\n- 已授权源码：")
	builder.WriteString(strings.Join(execution.Plan.SourceRoots, "、"))
	for _, source := range execution.Plan.SourceRoots {
		if strings.EqualFold(filepath.Ext(source), ".zip") {
			builder.WriteString("\n- ZIP 包可直接读取或解压，例如：unzip -q ")
			builder.WriteString(source)
			builder.WriteString(` -d "$SOPHON_WORKSPACE/src"`)
			break
		}
	}
	builder.WriteString("\n- 写入仅允许发生在当前会话工作区；上传目录和 artifact 目录只读。")
	return builder.String()
}

func continuationPromptForMission(ctx context.Context, decision finalizationDecision) string {
	execution, ok := missionExecutionFromContext(ctx)
	if !ok {
		return decision.continuationPrompt()
	}
	if execution.Plan.Mode == missionModeAssetInventory ||
		(execution.Plan.Mode == missionModeMixed && execution.Phase == missionPhaseAsset) {
		return "【资产阶段检查点】本轮只允许继续分析当前项目资产和攻击路径。" +
			"先调用 project_list(resource=\"assets\") 获取真实资产列表，再读取事实、漏洞、测试覆盖、图谱和 Next Targets，给出可继续挖掘的资产优先级。" +
			"如用户提供了新资产，可调用 project_insert_assets 登记。" +
			"禁止调用 exec、Python、MCP 网络工具或渗透子 Agent。完成资产整理后给出最终答复并结束。"
	}
	if execution.Plan.Mode == missionModeGeneral {
		return "【普通任务检查点】只继续完成用户要求的查询、解释或文档任务，禁止扩展为渗透测试。" +
			"完成后给出最终答复并结束。"
	}
	if execution.Plan.Mode == missionModeProjectWrite {
		return "【项目写操作检查点】只继续执行用户明确要求的项目数据修改，禁止调用网络探测或渗透子 Agent。" +
			"写操作完成后给出最终答复并结束。"
	}
	if execution.Phase == missionPhaseSourceAudit || execution.Phase == missionPhaseAppStatic {
		if execution.Plan.boundedFindingAudit() {
			return "【漏洞真实性核验检查点】只核验漏洞 " +
				strings.Join(execution.Plan.FindingIDs, "、") +
				"。不得扩大源码范围、扫描其他漏洞或派生后续意图。证据足够后输出 confirmed、refuted 或 insufficient_evidence 并停止。"
		}
		if execution.Plan.Mode == missionModeCodeAudit &&
			execution.AgentMode == agentModeDeep {
			return "【代码审计协调检查点】主 Agent 不得自行执行源码分析。" +
				"先调用 pent_agent_plan_hypotheses 建立工作单元，再用 project_list_hypotheses 获取假设，" +
				"通过 pent_agent_execute_hypothesis 分派 Worker，并汇总 Worker 写回的候选和证据。"
		}
		return "【本地分析检查点】优先继续读取和分析用户指定的本地源码或 App 包；网络请求仅允许访问活动项目授权范围内的目标。" +
			"给出带文件和行号证据的结论后结束当前阶段。"
	}
	if execution.Plan.Mode == missionModeRetest {
		return "【复测检查点】只继续复测原漏洞：" +
			strings.Join(execution.Plan.VulnerabilityIDs, "、") +
			"。不得探索其他漏洞，完成后必须调用 project_retest_finding 写回复测结果。"
	}
	if execution.Plan.Mode == missionModeCodeValidate || execution.Plan.Mode == missionModeAppValidation {
		return "【运行时验证检查点】只验证当前阶段明确授权的目标：" +
			formatMissionTargets(execution.Plan) +
			"。没有有效运行时证据时不得确认漏洞；完成当前阶段后结束。"
	}
	return decision.continuationPrompt()
}

func combineMissionOutput(assetSummary string, finalText string) string {
	assetSummary = strings.TrimSpace(assetSummary)
	finalText = strings.TrimSpace(finalText)
	switch {
	case assetSummary == "":
		return finalText
	case finalText == "":
		return assetSummary
	default:
		return assetSummary + "\n\n---\n\n" + finalText
	}
}

func resumePromptForMission(plan missionPlan, phase string) string {
	switch plan.Mode {
	case missionModeAssetInventory:
		return "【系统恢复请求】继续未完成的资产整理任务。只处理资产，不执行渗透测试；完成后结束。"
	case missionModeMixed:
		if phase == missionPhaseAsset {
			return "【系统恢复请求】继续未完成的资产整理阶段。禁止渗透；资产阶段完成后再由平台移交。"
		}
		return "【系统恢复请求】继续未完成的目标限定渗透任务。只测试：" + formatMissionTargets(plan) + "；不要扩展到其他资产。"
	case missionModeCodeAudit:
		return "【系统恢复请求】继续未完成的代码审计任务。优先分析指定源码目录；网络请求仅允许访问活动项目授权范围内的目标。"
	case missionModeCodeValidate:
		if phase == missionPhaseSourceAudit {
			return "【系统恢复请求】继续未完成的源码审计阶段。优先本地分析；网络请求仅允许访问活动项目授权范围内的目标。"
		}
		return "【系统恢复请求】继续未完成的代码漏洞验证阶段。只测试：" +
			formatMissionTargets(plan) + "；没有运行时证据不得确认漏洞。"
	case missionModeRetest:
		return "【系统恢复请求】继续未完成的漏洞复测：" +
			strings.Join(plan.VulnerabilityIDs, "、") +
			"；复测任务 ID：" + strings.Join(plan.RetestIDs, "、") +
			"；不要扩展到其他漏洞或资产。"
	case missionModeAppValidation:
		return "【系统恢复请求】继续未完成的 App 验证阶段：" + phase +
			"；不得更换 App 包或扩大后端目标范围。"
	case missionModeGeneral:
		return "【系统恢复请求】继续未完成的普通项目任务，不要扩展成渗透测试。"
	default:
		return "【系统恢复请求】继续未完成的限定范围渗透任务。只测试：" + formatMissionTargets(plan) + "；不要扩展到其他资产。"
	}
}

func missionClarificationMessage(plan missionPlan) string {
	reason := strings.TrimSpace(plan.Reason)
	if reason == "" {
		reason = "当前请求的任务类型或测试范围不明确"
	}
	return strings.TrimRight(reason, "。.!！") + "。"
}

func missionToolAllowed(plan missionPlan, phase string, toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	switch plan.Mode {
	case missionModeClarify:
		return false
	case missionModeAssetInventory:
		return assetInventoryToolAllowed(name)
	case missionModeGeneral:
		return generalMissionToolAllowed(name)
	case missionModeProjectWrite:
		return projectOperationToolAllowed(plan, name)
	case missionModeCodeAudit:
		return localAnalysisToolAllowed(name)
	case missionModeCodeValidate:
		if phase == missionPhaseSourceAudit {
			return localAnalysisToolAllowed(name)
		}
		return true
	case missionModeRetest:
		return retestToolAllowed(name)
	case missionModeAppValidation:
		if phase == missionPhaseAppStatic {
			return localAnalysisToolAllowed(name)
		}
		return true
	case missionModeMixed:
		if phase == missionPhaseAsset {
			return assetInventoryToolAllowed(name)
		}
	}
	return true
}

func localAnalysisToolAllowed(name string) bool {
	if isSubAgentEntryToolName(name) {
		// 本地分析阶段允许分派子 Agent；网络能力仍由 missionStageAllowsNetwork 收窄。
		return true
	}
	if !strings.HasPrefix(name, "project_") {
		switch name {
		case "exec", "execute-python-script", "mcp_use_tool", "read_artifact", readSkillToolName,
			searchProjectHistoryToolName, discoverProjectSourcesToolName:
			return true
		default:
			return !missionToolIsNetworkCapable(name, nil)
		}
	}
	switch name {
	case "project_list", "project_get", "project_list_assets", "project_asset_card", "project_list_facts",
		"project_record_fact", "project_record_audit", "project_list_findings", "project_get_finding", "project_report_finding",
		"project_next_targets", "project_plan_hypotheses", "project_list_hypotheses",
		"project_start_hypothesis", "project_complete_hypothesis", "project_record_test",
		"project_add_intent", "project_update_intent", "project_update_goal",
		"project_memory_graph", "project_query_memory", "project_graph_overview",
		"project_graph_node", "project_sync_graph":
		return true
	default:
		return false
	}
}

func mainCodeAuditCoordinatorToolAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == pentToolPlanHypotheses || name == pentToolExecuteHypothesis ||
		name == searchProjectHistoryToolName || name == discoverProjectSourcesToolName {
		return true
	}
	if strings.HasPrefix(name, "project_") || name == "read_artifact" {
		return true
	}
	return false
}

func retestToolAllowed(name string) bool {
	if isSubAgentEntryToolName(name) {
		return true
	}
	switch name {
	case "exec", "execute-python-script", "mcp_use_tool", "read_artifact", readSkillToolName,
		"project_list", "project_get", "project_list_findings", "project_get_finding", "project_list_facts", "project_record_fact",
		"project_get_retest_context", "project_update_finding", "project_retest_finding",
		"project_graph_overview", "project_graph_node":
		return true
	default:
		return false
	}
}

func missionRequiresAssetTool(plan missionPlan, phase string) bool {
	return plan.Mode == missionModeAssetInventory ||
		(plan.Mode == missionModeMixed && phase == missionPhaseAsset)
}

func missionStageAllowsNetwork(phase string) bool {
	switch phase {
	case missionPhasePentest,
		missionPhaseRuntimeValidate,
		missionPhaseRetest,
		missionPhaseAppRuntime,
		missionPhaseBackendValidate:
		return true
	default:
		return false
	}
}

func missionStageIsLocalAnalysis(plan missionPlan, phase string) bool {
	return phase == missionPhaseSourceAudit || phase == missionPhaseAppStatic
}

func assetInventoryToolAllowed(name string) bool {
	switch name {
	case "project_list", "project_get", "project_list_assets", "project_insert_assets", "project_asset_card",
		"project_list_facts", "project_query_memory", "project_list_findings", "project_get_finding",
		"project_next_targets", "project_list_hypotheses", "project_list_entities",
		"project_memory_graph", "project_conversation_entities", "project_fact_audit",
		"project_graph_overview", "project_graph_node", "project_list_chains",
		"project_campaign_overview", searchProjectHistoryToolName, discoverProjectSourcesToolName:
		return true
	default:
		return false
	}
}

func generalMissionToolAllowed(name string) bool {
	switch name {
	case readSkillToolName, "read_artifact", internetSearchToolName,
		"project_list", "project_get", "project_list_assets", "project_asset_card", "project_list_facts",
		"project_list_findings", "project_get_finding", "project_next_targets", "project_list_hypotheses",
		"project_list_entities", "project_memory_graph", "project_conversation_entities",
		"project_fact_audit", "project_graph_overview", "project_graph_node",
		"project_query_memory", "project_campaign_overview", "project_list_chains",
		searchProjectHistoryToolName, discoverProjectSourcesToolName:
		return true
	default:
		return false
	}
}

func projectOperationToolAllowed(plan missionPlan, name string) bool {
	if !strings.HasPrefix(name, "project_") {
		return false
	}
	for _, allowed := range plan.WriteTools {
		if strings.EqualFold(strings.TrimSpace(allowed), name) {
			return true
		}
	}
	return false
}

func (s *Service) activeToolsForMission(
	ctx context.Context,
	mode string,
	plan missionPlan,
	phase string,
) []tool.BaseTool {
	if plan.Mode == missionModeClarify {
		return nil
	}
	items := s.activeToolsForMode(ctx, mode)
	filtered := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		info, err := item.Info(ctx)
		if err != nil || info == nil || !missionToolAllowed(plan, phase, info.Name) {
			continue
		}
		if normalizeAgentMode(mode) == agentModeDeep &&
			plan.Mode == missionModeCodeAudit &&
			phase == missionPhaseSourceAudit &&
			!mainCodeAuditCoordinatorToolAllowed(info.Name) {
			continue
		}
		if normalizeAgentMode(mode) == agentModeDeep &&
			phase == missionPhasePentest &&
			!isSubAgentEntryToolName(info.Name) &&
			!strings.HasPrefix(info.Name, "project_") &&
			info.Name != readSkillToolName &&
			info.Name != "read_artifact" &&
			info.Name != searchProjectHistoryToolName &&
			info.Name != discoverProjectSourcesToolName &&
			info.Name != internetSearchToolName {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func (s *Service) contextAgentTools(ctx context.Context) []tool.BaseTool {
	if execution, ok := missionExecutionFromContext(ctx); ok {
		return s.activeToolsForMission(
			ctx,
			execution.AgentMode,
			execution.Plan,
			execution.Phase,
		)
	}
	return s.activeTools(ctx)
}

func (s *Service) missionToolDecision(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
) (bool, string) {
	execution, ok := missionExecutionFromContext(ctx)
	if !ok {
		return true, ""
	}
	plainName := s.plainToolName(toolName)
	if completed, _, _ := missionObjectiveCompletion(ctx); completed {
		switch {
		case isSubAgentEntryToolName(plainName):
			return false, "明确目标已完成，禁止继续启动新的子 Agent"
		case plainName == "exec",
			plainName == "execute-python-script",
			plainName == "mcp_use_tool":
			return false, "明确目标已完成，禁止继续执行新的工具任务"
		}
	}
	if execution.AgentMode == agentModeDeep &&
		execution.Plan.Mode == missionModeCodeAudit &&
		execution.Phase == missionPhaseSourceAudit {
		if _, inSubagent := execctx.Subagent(ctx); !inSubagent &&
			!mainCodeAuditCoordinatorToolAllowed(plainName) {
			return false, "代码审计主 Agent 只负责规划和调度；源码分析必须通过 Planner/Worker 执行"
		}
	}
	if plainName == "project_list" || plainName == "project_get" {
		resource, _ := args["resource"].(string)
		if allowed, reason := projectReadResourceMissionDecision(execution, plainName, resource); !allowed {
			return false, reason
		}
	}
	if execution.AgentMode == agentModeDeep &&
		execution.Phase == missionPhasePentest {
		if _, inSubagent := execctx.Subagent(ctx); !inSubagent &&
			!isSubAgentEntryToolName(plainName) &&
			!strings.HasPrefix(plainName, "project_") &&
			plainName != readSkillToolName &&
			plainName != "read_artifact" &&
			plainName != searchProjectHistoryToolName &&
			plainName != discoverProjectSourcesToolName &&
			plainName != internetSearchToolName {
			return false, "Deep Path 渗透阶段必须通过 pent_agent_execute 交给受限子 Agent 执行"
		}
	}
	if !missionToolAllowed(execution.Plan, execution.Phase, plainName) {
		return false, fmt.Sprintf(
			"当前意图阶段 %s/%s 不允许调用工具 %s",
			execution.Plan.Mode,
			execution.Phase,
			plainName,
		)
	}
	networkCapable := missionToolIsNetworkCapable(plainName, args)
	if !missionStageAllowsNetwork(execution.Phase) && !networkCapable {
		if allowed, reason := s.missionLocalPathsAllowed(ctx, execution.Plan, args); !allowed {
			return false, reason
		}
		return true, ""
	}
	if missionAuthorizationScopeExempt(plainName) {
		return true, ""
	}
	if execution.Plan.ProjectScope ||
		(len(execution.Scope.Hosts) == 0 && len(execution.Scope.AuthorizedScopes) == 0) {
		return true, ""
	}
	if !networkCapable {
		return true, ""
	}
	targets := missionNetworkTargets(plainName, args)
	if len(targets) == 0 {
		return true, ""
	}
	authorized := false
	for _, target := range targets {
		if missionScopeIncludesTarget(execution.Scope, target) {
			authorized = true
			break
		}
	}
	if !authorized {
		return false, fmt.Sprintf(
			"任务目标限制：%s 均不在本轮明确授权目标 %s 内",
			strings.Join(targets, "、"),
			strings.Join(execution.Scope.Hosts, "、"),
		)
	}
	return true, ""
}

func missionAuthorizationScopeExempt(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "exec", "execute-python-script":
		return true
	default:
		return false
	}
}

func projectReadResourceMissionDecision(
	execution missionExecution,
	toolName string,
	resource string,
) (bool, string) {
	resource = strings.ToLower(strings.TrimSpace(resource))
	var legacyName string
	var ok bool
	switch toolName {
	case "project_list":
		legacyName, ok = legacyProjectListToolName(resource)
	case "project_get":
		legacyName, ok = legacyProjectGetToolName(resource)
	default:
		return true, ""
	}
	if !ok {
		return false, fmt.Sprintf("%s 必须指定有效的 resource", toolName)
	}
	if !missionToolAllowed(execution.Plan, execution.Phase, toolName) {
		return false, fmt.Sprintf(
			"当前意图阶段 %s/%s 不允许调用工具 %s",
			execution.Plan.Mode,
			execution.Phase,
			toolName,
		)
	}
	if !missionToolAllowed(execution.Plan, execution.Phase, legacyName) {
		return false, fmt.Sprintf(
			"当前意图阶段 %s/%s 不允许调用 %s resource=%s",
			execution.Plan.Mode,
			execution.Phase,
			toolName,
			resource,
		)
	}
	return true, ""
}

func authorizeProjectReadResource(ctx context.Context, toolName, resource string) error {
	execution, ok := missionExecutionFromContext(ctx)
	if !ok {
		return nil
	}
	if allowed, reason := projectReadResourceMissionDecision(execution, toolName, resource); !allowed {
		return fmt.Errorf("Mission Policy 拒绝执行 %s：%s", toolName, reason)
	}
	return nil
}

func (s *Service) missionLocalPathsAllowed(
	ctx context.Context,
	plan missionPlan,
	args map[string]interface{},
) (bool, string) {
	if s == nil {
		return false, "本地路径策略不可用"
	}
	var content strings.Builder
	collectProbeStrings(args, &content)
	text := strings.TrimSpace(content.String())
	if text == "" {
		return true, ""
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "../") || strings.Contains(lower, "cd ..") {
		return false, "本地分析禁止使用可逃逸工作区的相对路径"
	}
	pathPolicyText := strings.ReplaceAll(lower, "/dev/null", "")
	for _, marker := range []string{
		"~/", "$home", "${home}", "/root/", "/etc/", "/proc/", "/sys/", "/dev/",
	} {
		if strings.Contains(pathPolicyText, marker) {
			return false, "本地分析禁止访问工作区外敏感路径"
		}
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return false, "存储根目录未配置，无法校验本地路径"
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return false, "无法解析存储根目录"
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	workspace := filepath.Join(root, "tmp", "workspace", conversationID)
	allowedRoots := []string{workspace}
	readHints := []string{workspace}
	if conversationID != "" {
		for _, path := range []string{
			filepath.Join(root, "chat_uploads", conversationID),
			filepath.Join(root, "data", "conversation_artifacts", conversationID),
		} {
			allowedRoots = append(allowedRoots, path)
			readHints = append(readHints, path)
		}
	}
	allowedFiles := map[string]bool{}
	for _, source := range plan.SourceRoots {
		absolute, err := filepath.Abs(source)
		if err != nil {
			continue
		}
		if info, statErr := os.Stat(absolute); statErr == nil && info.IsDir() {
			allowedRoots = append(allowedRoots, absolute)
		} else {
			allowedFiles[filepath.Clean(absolute)] = true
		}
		readHints = append(readHints, absolute)
	}
	for _, artifact := range plan.AppArtifacts {
		absolute, err := filepath.Abs(artifact)
		if err == nil {
			allowedFiles[filepath.Clean(absolute)] = true
			readHints = append(readHints, absolute)
		}
	}
	for _, match := range missionSourcePathPattern.FindAllStringSubmatchIndex(text, -1) {
		if len(match) < 4 || match[2] < 0 || match[3] <= match[2] {
			continue
		}
		if missionPathCandidateIsVariableSuffix(text, match[2]) {
			continue
		}
		if missionPathCandidateIsCommandPattern(text, match[2], match[3]) {
			continue
		}
		value := strings.TrimSpace(text[match[2]:match[3]])
		if missionPathLooksWriteTarget(text, match[2], match[3]) &&
			!missionPathWithinRoot(value, workspace) {
			suggested := "$SOPHON_WORKSPACE/" + strings.TrimPrefix(filepath.ToSlash(value), "/")
			return false, fmt.Sprintf(
				"本地路径超出当前会话写入范围：%s；本地分析只允许写入当前会话工作区；请改用 %s（实际目录：%s）",
				value,
				suggested,
				workspace,
			)
		}
		if strings.HasPrefix(value, "/bin/") ||
			strings.HasPrefix(value, "/usr/bin/") ||
			strings.HasPrefix(value, "/usr/local/bin/") {
			continue
		}
		absolute, err := filepath.Abs(value)
		if err != nil {
			return false, "无法解析本地路径：" + value
		}
		if allowedFiles[filepath.Clean(absolute)] {
			continue
		}
		allowed := false
		for _, allowedRoot := range allowedRoots {
			allowedRoot, err = filepath.Abs(allowedRoot)
			if err != nil {
				continue
			}
			rel, err := filepath.Rel(allowedRoot, absolute)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			suggested := "$SOPHON_WORKSPACE/" + strings.TrimPrefix(filepath.ToSlash(value), "/")
			return false, fmt.Sprintf(
				"本地路径超出源码、工作区或 App 包范围：%s；请改用相对路径或 %s；当前会话已授权输入：%s",
				value,
				suggested,
				strings.Join(limitedStrings(readHints, 4), "、"),
			)
		}
	}
	return true, ""
}

func missionPathLooksWriteTarget(text string, start, end int) bool {
	if start <= 0 || end <= start {
		return false
	}
	prefixStart := start - 80
	if prefixStart < 0 {
		prefixStart = 0
	}
	prefix := strings.TrimRight(text[prefixStart:start], " \t'\"")
	for _, marker := range []string{">", ">>", "-d", "--output", "--output-document", "-C"} {
		if strings.HasSuffix(prefix, marker) {
			return true
		}
	}
	segmentStart := strings.LastIndexAny(text[:start], ";\n|&") + 1
	segment := strings.TrimSpace(text[segmentStart:start])
	fields := strings.Fields(segment)
	if len(fields) == 0 {
		return false
	}
	command := strings.ToLower(filepath.Base(fields[0]))
	switch command {
	case "tee", "touch", "mkdir", "rm", "rmdir", "truncate", "chmod", "chown", "ln":
		return true
	case "cp", "mv", "install", "rsync":
		suffix := text[end:]
		if index := strings.IndexAny(suffix, ";\n|&"); index >= 0 {
			suffix = suffix[:index]
		}
		return strings.TrimSpace(strings.Trim(suffix, " \t'\"")) == ""
	case "sed":
		for _, field := range fields[1:] {
			if field == "-i" || strings.HasPrefix(field, "-i") {
				return true
			}
		}
	}
	return false
}

func missionPathWithinRoot(path, root string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(root, absolute)
	return err == nil &&
		relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func limitedStrings(values []string, limit int) []string {
	result := make([]string, 0, limit)
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
		if len(result) >= limit {
			break
		}
	}
	return result
}

func missionPathCandidateIsCommandPattern(text string, start, end int) bool {
	if start <= 0 || end <= start || end >= len(text) {
		return false
	}
	quote := text[start-1]
	if quote != '\'' && quote != '"' {
		return false
	}
	if !strings.ContainsRune(text[end:], rune(quote)) {
		return false
	}
	segmentStart := strings.LastIndexAny(text[:start], ";\n|&") + 1
	segment := strings.TrimSpace(text[segmentStart:start])
	fields := strings.Fields(segment)
	if len(fields) == 0 {
		return false
	}
	command := filepath.Base(fields[0])
	switch command {
	case "awk", "sed", "grep", "egrep", "rg":
	default:
		return false
	}
	if command == "awk" || command == "sed" {
		for _, field := range fields[1:] {
			if field == "-f" {
				return false
			}
		}
	}
	return true
}

func missionPathCandidateIsVariableSuffix(text string, start int) bool {
	if start <= 1 || start >= len(text) {
		return false
	}
	quote := text[start-1]
	if quote != '\'' && quote != '"' {
		return false
	}
	prefixStart := start - 80
	if prefixStart < 0 {
		prefixStart = 0
	}
	prefix := strings.TrimSpace(text[prefixStart:start])
	if index := strings.LastIndexAny(prefix, " \t;\n|&("); index >= 0 {
		prefix = strings.TrimSpace(prefix[index+1:])
	}
	return strings.Contains(prefix, "$")
}

func missionToolIsNetworkCapable(toolName string, args map[string]interface{}) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if isSubAgentEntryToolName(name) {
		return true
	}
	if name == internetSearchToolName {
		return true
	}
	if name == "mcp_use_tool" {
		var content strings.Builder
		collectProbeStrings(args, &content)
		lower := strings.ToLower(content.String())
		if containsAnyText(lower,
			"apk", "ipa", "jadx", "apktool", "mobsf", "semgrep", "code_search",
			"static_analysis", "source_audit",
		) && !containsAnyText(lower, "http://", "https://", " curl ", " install ") {
			return false
		}
		return true
	}
	for _, marker := range []string{
		"http", "curl", "wget", "request", "scan", "nmap", "nuclei", "sqlmap",
		"ffuf", "gobuster", "dirsearch", "nikto", "masscan", "naabu", "httpx",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	var content strings.Builder
	collectProbeStrings(args, &content)
	text := strings.ToLower(content.String())
	for _, marker := range []string{
		"curl ", "wget ", "nmap ", "nuclei ", "sqlmap ", "ffuf ", "gobuster ",
		"dirsearch ", "nikto ", "masscan ", "naabu ", "httpx ", "openssl s_client",
		"import requests", "from requests", "requests.", "httpx.", "aiohttp",
		"from http import client", "http.client", "urllib.request",
		"socket.connect", "socket.socket", "python ", "python3 ", "bash ",
		".py ", ".sh ",
		" -il ", " -iL ", "targets.txt", "hosts.txt",
	} {
		if strings.Contains(text, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func missionNetworkTargets(toolName string, args map[string]interface{}) []string {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "exec":
		command, _ := args["command"].(string)
		return normalizeMissionTargets(policy.AnalyzeCommand(command).Targets)
	case "execute-python-script":
		script, _ := args["script"].(string)
		return normalizeMissionTargets(policy.AnalyzePythonScript(script).Targets)
	case internetSearchToolName:
		return nil
	}
	var content strings.Builder
	collectProbeStrings(args, &content)
	text := content.String()
	hosts := map[string]bool{}
	for _, host := range probeHostPattern.FindAllString(text, -1) {
		hosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
	for _, host := range probeIPPattern.FindAllString(text, -1) {
		hosts[strings.ToLower(strings.TrimSpace(host))] = true
	}
	for _, rawURL := range probeURLPattern.FindAllString(text, -1) {
		parsed, err := url.Parse(strings.TrimRight(rawURL, ".,;)"))
		if err == nil && strings.TrimSpace(parsed.Hostname()) != "" {
			hosts[strings.ToLower(strings.TrimSpace(parsed.Hostname()))] = true
		}
	}
	return normalizeMissionTargets(limitedSortedKeys(hosts, 0))
}

func missionScopeIncludesTarget(scope missionScope, target string) bool {
	target = normalizeMissionTarget(target)
	if target == "" {
		return true
	}
	for _, host := range scope.Hosts {
		if strings.EqualFold(strings.TrimSpace(host), target) {
			return true
		}
	}
	return targetAllowedByAuthorizedScopes(target, scope.AuthorizedScopes)
}
