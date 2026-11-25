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
	Coordinated        bool     `json:"coordinated,omitempty"`
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
		if plan.Mode == missionModeAgent {
			plan = s.coordinateMainAgentPlan(
				ctx,
				userID,
				project.ID,
				conversation.ID,
				plan,
				plan.Objective+"\n"+resumeMessage,
			)
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
			Coordinated:  true,
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
	return s.coordinatedDirectMainAgentPlan(
		ctx,
		userID,
		project.ID,
		project,
		conversation,
		assets,
		message,
	)
}

func (s *Service) coordinatedDirectMainAgentPlan(
	ctx context.Context,
	userID string,
	projectID string,
	project database.Project,
	conversation database.Conversation,
	assets []database.Asset,
	message string,
) missionPlan {
	plan := directMainAgentPlan(project, conversation, assets, message)
	return s.coordinateMainAgentPlan(
		ctx,
		userID,
		projectID,
		conversation.ID,
		plan,
		message,
	)
}

func (s *Service) coordinateMainAgentPlan(
	ctx context.Context,
	_ string,
	projectID string,
	conversationID string,
	plan missionPlan,
	_ string,
) missionPlan {
	if plan.Mode != missionModeAgent {
		return plan
	}
	coordinatedRuntime := false
	if s != nil {
		if handle := s.orchestrationFor(conversationID); handle != nil {
			status, _ := handle.snapshot()["status"].(string)
			coordinatedRuntime = status == database.AgentOrchestrationRunning ||
				status == database.AgentOrchestrationPaused
		}
		if !coordinatedRuntime && s.db != nil {
			if records, err := s.db.ListRecoverableAgentOrchestrations(ctx); err == nil {
				for _, record := range records {
					if record.ConversationID == conversationID &&
						record.ProjectID == projectID &&
						(record.Status == database.AgentOrchestrationRunning ||
							record.Status == database.AgentOrchestrationPaused) {
						coordinatedRuntime = true
						break
					}
				}
			}
		}
		if !coordinatedRuntime && s.db != nil {
			if active, err := s.db.CountActiveProjectHypothesesForConversation(
				ctx,
				projectID,
				conversationID,
			); err == nil && active > 0 {
				coordinatedRuntime = true
			}
		}
	}
	if len(normalizeMissionTargets(plan.PentestTargets)) == 0 && !coordinatedRuntime {
		return plan
	}
	plan.Coordinated = true
	reason := "目标任务预测比较复杂时启用 Planner/Worker 协调"
	if strings.TrimSpace(plan.Reason) == "" {
		plan.Reason = reason
	} else {
		plan.Reason = strings.TrimSpace(plan.Reason) + "；" + reason
	}
	return plan
}

func (s *Service) projectSourceInputs(
	ctx context.Context,
	userID string,
	projectID string,
	conversationID string,
) []string {
	roots, _ := s.projectSourceRoots(ctx, projectID, userID)
	if len(roots) > 0 {
		return roots
	}
	if s == nil || s.db == nil {
		return nil
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return nil
	}
	conversations, err := s.db.ListProjectConversations(ctx, projectID, userID)
	if err != nil {
		return nil
	}
	sort.SliceStable(conversations, func(i, j int) bool {
		return conversations[i].ID == conversationID && conversations[j].ID != conversationID
	})
	const maxScannedEntries = 5000
	scanned := 0
	for _, conversation := range conversations {
		paths, pathErr := s.agentWorkspacePathsFor(projectID, conversation.ID)
		if pathErr != nil {
			continue
		}
		bases := []string{filepath.Join(root, "chat_uploads", conversation.ID)}
		bases = append(bases, paths.conversationDirs()...)
		for _, base := range bases {
			if info, statErr := os.Stat(base); statErr != nil || !info.IsDir() {
				continue
			}
			found := ""
			walkErr := filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil || entry == nil {
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					if entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if entry.IsDir() {
					return nil
				}
				scanned++
				if scanned > maxScannedEntries {
					return filepath.SkipAll
				}
				if isLikelySourceFile(path) {
					found = filepath.Dir(path)
					return filepath.SkipAll
				}
				return nil
			})
			if walkErr != nil && walkErr != filepath.SkipAll {
				continue
			}
			if found != "" {
				return []string{found}
			}
		}
	}
	return nil
}

func isLikelySourceFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".java", ".py", ".rb", ".php",
		".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".kt", ".kts",
		".scala", ".sh", ".sql", ".html", ".htm", ".aspx", ".ashx", ".asmx", ".sln", ".csproj":
		return true
	default:
		return false
	}
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
		Reason:             "系统 Agent 为漏洞复测且消息绑定了当前项目中的有效 finding ID",
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

func missionModeUsesCoordinator(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case missionModeCodeAudit, missionModeCodeValidate, missionModePentest,
		missionModeAppValidation:
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
	_ = phase
	if plan.Coordinated {
		return "\n\n【执行上下文】\n" +
			"当前任务由 Planner/Worker 协同执行。你负责观察、操舵、审核关键结果和向人工汇总；" +
			"不得亲自运行命令、脚本、扫描器或 MCP 工具，也不得重复 Worker 已经执行的工作。"
	}
	return "\n\n【执行上下文】\n" +
		"当前用户、项目、目标、附件、finding 和项目状态仅作为上下文。" +
		"执行方式必须服从当前 Agent 模式约束；完成当前任务后停止。"
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

func mainAgentExecutionContext(plan missionPlan) string {
	var builder strings.Builder
	builder.WriteString("\n\n【执行上下文】\n")
	if plan.Coordinated {
		builder.WriteString("当前运行方式：主 Agent + Planner/Worker 协同模式。平台已启动后台编排，本轮不直接执行工具。\n")
	} else {
		builder.WriteString("当前运行方式：主 Agent 独立执行模式。平台已关闭 Planner、Worker 和 pent_agent_* 入口。\n")
	}
	if objective := strings.TrimSpace(plan.Objective); objective != "" {
		builder.WriteString("当前任务目标：")
		builder.WriteString(objective)
		builder.WriteString("\n")
	}
	if targets := formatMissionTargets(plan); targets != "" && targets != "未指定" {
		builder.WriteString("当前目标范围：")
		builder.WriteString(targets)
		builder.WriteString("\n")
	}
	builder.WriteString("当前用户、项目、目标、附件、finding 和项目状态仅作为上下文；完成当前任务后停止。")
	return builder.String()
}

func (s *Service) mainAgentInstruction(ctx context.Context) string {
	instruction := s.systemAgentPrompt(
		ctx,
		SystemMainAgentID,
		SystemMainAgentName,
		mainAgentPrompt,
	)
	if execution, ok := missionExecutionFromContext(ctx); ok {
		instruction += mainAgentExecutionContext(
			execution.Plan,
		)
	}
	if agentPrompt := s.conversationSystemAgentPrompt(ctx); strings.TrimSpace(agentPrompt) != "" {
		instruction = agentPrompt + "\n\n" + instruction
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if execution, coordinated := missionExecutionFromContext(ctx); s != nil && s.db != nil &&
		(!coordinated || !execution.Plan.Coordinated) {
		if conversationID != "" && userID != "" {
			if state, err := s.db.GetZhiziConversationState(ctx, conversationID, userID); err == nil &&
				state.Enabled && state.Lease != nil {
				instruction += zhiziExecutionPriorityGuidance(state.Lease.Node.Name)
			}
		}
	}
	return withPlatformVerificationWorkflow(instruction)
}

func (s *Service) conversationSystemAgentPrompt(ctx context.Context) string {
	if s == nil || s.db == nil {
		return ""
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return ""
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		return ""
	}
	switch strings.TrimSpace(conversation.AgentRoleID) {
	case SystemRetestAgentID:
		return s.systemAgentPrompt(
			ctx,
			SystemRetestAgentID,
			SystemRetestAgentName,
			retestAgentPrompt,
		)
	default:
		return ""
	}
}

func zhiziExecutionPriorityGuidance(nodeName string) string {
	nodeName = strings.TrimSpace(nodeName)
	var builder strings.Builder
	builder.WriteString("\n\n【智子分身执行优先级（强约束）】\n")
	if nodeName != "" {
		builder.WriteString("当前会话已绑定可用的智子分身 VPS：")
		builder.WriteString(nodeName)
		builder.WriteString("。\n")
	} else {
		builder.WriteString("当前会话已绑定可用的智子分身 VPS。\n")
	}
	builder.WriteString("1. shell 命令、Python、脚本、扫描器、文件处理、上传下载和网络请求，必须首先选择 zhizi_exec、zhizi_python、zhizi_upload、zhizi_download。\n")
	builder.WriteString("2. 当前会话的本地 exec、execute-python-script、install-python-package、java_decompile 和其余 sophon-tool-runner 工具已被禁用，调用会被拒绝。\n")
	builder.WriteString("3. 智子工具失败时只报告错误或重试智子工具，不得回退到本地 shell、本地扫描器或其他本地执行工具。\n")
	builder.WriteString("4. 项目元数据、read_skill、read_artifact、project_* 等控制面操作仍可本地执行；这些工具不用于运行命令或扫描。\n")
	builder.WriteString("5. 不要要求用户提供 SSH 凭据；智子连接由当前对话租约管理。")
	return builder.String()
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
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	var builder strings.Builder
	builder.WriteString("\n\n源码输入访问规则：")
	builder.WriteString("可直接读取同一用户、同一项目下所有对话的上传文件；禁止读取其他项目、其他用户、/opt/sophon 根目录、父目录或非授权系统路径。\n")
	builder.WriteString("- 当前项目公共上传目录：")
	builder.WriteString(filepath.Join(root, "chat_uploads"))
	builder.WriteString("\n- 当前会话上传目录：")
	builder.WriteString(filepath.Join(root, "chat_uploads", conversationID))
	if paths, pathErr := s.agentWorkspacePathsFor(projectID, conversationID); pathErr == nil {
		builder.WriteString("\n- 当前项目工作区：")
		builder.WriteString(paths.ProjectRoot)
		builder.WriteString("\n- 当前会话工作区：")
		builder.WriteString(paths.ConversationRoot)
	}
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
	_ = ctx
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

func resumePromptForMission(plan missionPlan, _ string) string {
	context := ""
	if targets := formatMissionTargets(plan); targets != "" {
		context = " 当前目标：" + targets + "。"
	}
	return "【系统恢复请求】继续完成当前用户请求。" + context +
		" 如无更多必要工作，直接总结结果并结束。"
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
			searchProjectHistoryToolName, discoverProjectSourcesToolName,
			orchestratorControlToolName:
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
		"project_add_goal", "project_add_hint",
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
	if name == "exec" || name == "execute-python-script" {
		return true
	}
	if strings.HasPrefix(name, "project_") || name == "read_artifact" {
		return true
	}
	return false
}

func coordinatedMainToolAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case searchProjectHistoryToolName, discoverProjectSourcesToolName,
		"read_artifact", orchestratorControlToolName:
		return true
	}
	switch name {
	case "project_add_intent", "project_update_intent", "project_update_goal",
		"project_add_goal", "project_add_hint", "project_record_fact":
		return true
	}
	return coordinatedProjectReadToolAllowed(name)
}

func plannerRoleToolAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == plannerTodoListToolName || name == plannerTodoUpdateToolName {
		return true
	}
	switch name {
	case "project_plan_hypotheses", "project_plan_frontier", "read_artifact",
		"project_prove_goal",
		searchProjectHistoryToolName, discoverProjectSourcesToolName,
		orchestratorControlToolName:
		return true
	}
	return coordinatedProjectReadToolAllowed(name)
}

func workerRoleToolAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasPrefix(name, "project_") {
		return true
	}
	switch name {
	case "project_start_hypothesis", "project_complete_hypothesis",
		"project_record_fact", "project_record_audit", "project_report_finding",
		"project_update_finding", "project_verify_finding", "project_record_test",
		"project_retest_finding", "project_record_link", "project_upsert_entity",
		"project_link_entities", "project_insert_assets":
		return true
	}
	return coordinatedProjectReadToolAllowed(name)
}

func coordinatedProjectReadToolAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "project_next_targets", "project_asset_card", "project_fact_audit":
		return true
	}
	for _, prefix := range []string{
		"project_list", "project_get", "project_query", "project_memory",
		"project_graph_overview", "project_graph_node", "project_conversation_",
		"project_campaign_overview", "project_campaign_frontier",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
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
		intelSearchToolName,
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
	case readSkillToolName, "read_artifact", internetSearchToolName, intelSearchToolName,
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
	_ string,
) []tool.BaseTool {
	items := s.activeToolsForMode(ctx, mode)
	if !plan.Coordinated || normalizeAgentMode(mode) == agentModeFast {
		return items
	}
	filtered := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		info, err := item.Info(ctx)
		if err != nil || info == nil || !coordinatedMainToolAllowed(info.Name) {
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
	if normalizeAgentMode(execctx.RunMode(ctx)) == agentModeFast {
		if isSubAgentEntryToolName(plainName) {
			return false, "当前为单 Agent 模式，禁止调用 Planner/Worker"
		}
		if plainName == orchestratorControlToolName &&
			!fastModeOrchestratorActionAllowed(modeStringArg(args, "action")) {
			return false, "单 Agent 模式只允许查看或停止历史 Worker，不能启动、恢复或纠偏编排"
		}
	}
	if s.isLocalExecutionTool(plainName) {
		if blocked, reason := s.localExecutionBlockedByZhizi(ctx); blocked {
			return false, reason
		}
	}
	networkCapable := missionToolIsNetworkCapable(plainName, args)
	if !execctx.AssetRestrictionEnabled(ctx) {
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

func projectReadResourceMissionDecision(
	_ missionExecution,
	toolName string,
	resource string,
) (bool, string) {
	resource = strings.ToLower(strings.TrimSpace(resource))
	var ok bool
	switch toolName {
	case "project_list":
		_, ok = legacyProjectListToolName(resource)
	case "project_get":
		_, ok = legacyProjectGetToolName(resource)
	default:
		return true, ""
	}
	if !ok {
		return false, fmt.Sprintf("%s 必须指定有效的 resource", toolName)
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

func missionToolIsNetworkCapable(toolName string, args map[string]interface{}) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if isSubAgentEntryToolName(name) {
		return true
	}
	if name == internetSearchToolName || name == intelSearchToolName {
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
	case "exec", zhiziExecToolName:
		command, _ := args["command"].(string)
		return normalizeMissionTargets(policy.AnalyzeCommand(command).Targets)
	case "execute-python-script", zhiziPythonToolName:
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
