package execctx

import (
	"context"
	"strings"
	"sync"
)

type conversationIDKey struct{}
type userIDKey struct{}
type messageIDKey struct{}
type assetIDKey struct{}
type campaignIDKey struct{}
type campaignTaskIDKey struct{}
type autoContinueKey struct{}
type assetRestrictionKey struct{}
type projectIDKey struct{}
type runIDKey struct{}
type runModeKey struct{}
type authorizedScopesKey struct{}
type subagentKey struct{}
type progressKey struct{}

// ProgressFunc forwards a child-agent event to the active run stream.
// The callback intentionally uses primitive fields so execctx does not depend
// on the agent package.
type ProgressFunc func(eventType string, message string, data map[string]interface{}) error

// SkillGate 记录 Worker 是否已经加载过至少一个分配技能正文。
// 该状态跨工具调用共享，但不会跨 Worker 复用。
type SkillGate struct {
	mu            sync.Mutex
	required      map[string]bool
	requiredOrder []string
	loaded        map[string]bool
}

func NewSkillGate(required ...string) *SkillGate {
	gate := &SkillGate{
		required: map[string]bool{},
		loaded:   map[string]bool{},
	}
	for _, name := range required {
		if name = strings.TrimSpace(name); name != "" {
			if !gate.required[name] {
				gate.required[name] = true
				gate.requiredOrder = append(gate.requiredOrder, name)
			}
		}
	}
	return gate
}

func (g *SkillGate) MarkLoaded(name string) {
	if g == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	g.mu.Lock()
	g.loaded[name] = true
	g.mu.Unlock()
}

func (g *SkillGate) Ready() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.required) > 0 {
		for name := range g.required {
			if !g.loaded[name] {
				return false
			}
		}
		return true
	}
	return len(g.loaded) > 0
}

func (g *SkillGate) MissingRequired() []string {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	missing := make([]string, 0, len(g.requiredOrder))
	for _, name := range g.requiredOrder {
		if !g.loaded[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// SubagentInfo 描述当前执行上下文所属的子 Agent 及其能力边界。
// Mode 为空表示未启用能力模式限制；Depth 为 0 表示当前不在子 Agent 内。
type SubagentInfo struct {
	ID           string
	Name         string
	Kind         string
	ParentID     string
	IntentID     string
	HypothesisID string
	Mode         string
	Depth        int
	// WorkerFocus 是主 Agent 为本次子任务指定的工作身份，不替代用户角色。
	WorkerFocus string
	// AllowedSkills 是当前 Worker 可读取的角色技能子集；空表示继承角色全部技能。
	AllowedSkills []string
	// RequiredSkills 是本次 Worker 首次实质操作前必须全部加载的技能正文。
	RequiredSkills []string
	// SkillGate 为 nil 时不做首次技能读取门禁。
	SkillGate *SkillGate
	// CPUSeconds 和 MaxProcesses 会传给工具执行器，用于限制受限进程组。
	CPUSeconds   int
	MaxProcesses int
	// MCPScope 限制子 Agent 可继承的 MCP 工具：空表示全部继承。
	MCPScope []string
}

func WithSubagent(ctx context.Context, info SubagentInfo) context.Context {
	info.AllowedSkills = append([]string(nil), info.AllowedSkills...)
	info.RequiredSkills = append([]string(nil), info.RequiredSkills...)
	return context.WithValue(ctx, subagentKey{}, info)
}

// Subagent 返回当前子 Agent 信息，非子 Agent 上下文返回 false。
func Subagent(ctx context.Context) (SubagentInfo, bool) {
	info, ok := ctx.Value(subagentKey{}).(SubagentInfo)
	return info, ok
}

func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, fn)
}

func Progress(ctx context.Context) (ProgressFunc, bool) {
	fn, ok := ctx.Value(progressKey{}).(ProgressFunc)
	return fn, ok && fn != nil
}

func WithProjectID(ctx context.Context, projectID string) context.Context {
	return context.WithValue(ctx, projectIDKey{}, projectID)
}

func ProjectID(ctx context.Context) string {
	value, _ := ctx.Value(projectIDKey{}).(string)
	return value
}

func WithRunID(ctx context.Context, runID string) context.Context {
	return context.WithValue(ctx, runIDKey{}, runID)
}

func RunID(ctx context.Context) string {
	value, _ := ctx.Value(runIDKey{}).(string)
	return value
}

func WithRunMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, runModeKey{}, mode)
}

func RunMode(ctx context.Context) string {
	value, _ := ctx.Value(runModeKey{}).(string)
	return value
}

// WithAuthorizedScopes attaches target ranges authorized only for the current run.
// The agent package normalizes and validates these values before attaching them.
func WithAuthorizedScopes(ctx context.Context, scopes []string) context.Context {
	if len(scopes) == 0 {
		return ctx
	}
	items := append([]string(nil), scopes...)
	return context.WithValue(ctx, authorizedScopesKey{}, items)
}

func AuthorizedScopes(ctx context.Context) []string {
	items, _ := ctx.Value(authorizedScopesKey{}).([]string)
	return append([]string(nil), items...)
}

func WithConversationID(ctx context.Context, conversationID string) context.Context {
	return context.WithValue(ctx, conversationIDKey{}, conversationID)
}

func ConversationID(ctx context.Context) string {
	value, _ := ctx.Value(conversationIDKey{}).(string)
	return value
}

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

func UserID(ctx context.Context) string {
	value, _ := ctx.Value(userIDKey{}).(string)
	return value
}

func WithMessageID(ctx context.Context, messageID string) context.Context {
	return context.WithValue(ctx, messageIDKey{}, messageID)
}

func MessageID(ctx context.Context) string {
	value, _ := ctx.Value(messageIDKey{}).(string)
	return value
}

func WithAssetID(ctx context.Context, assetID string) context.Context {
	return context.WithValue(ctx, assetIDKey{}, assetID)
}

func AssetID(ctx context.Context) string {
	value, _ := ctx.Value(assetIDKey{}).(string)
	return value
}

func WithCampaignID(ctx context.Context, campaignID string) context.Context {
	return context.WithValue(ctx, campaignIDKey{}, campaignID)
}

func CampaignID(ctx context.Context) string {
	value, _ := ctx.Value(campaignIDKey{}).(string)
	return value
}

func WithCampaignTaskID(ctx context.Context, taskID string) context.Context {
	return context.WithValue(ctx, campaignTaskIDKey{}, taskID)
}

func CampaignTaskID(ctx context.Context) string {
	value, _ := ctx.Value(campaignTaskIDKey{}).(string)
	return value
}

func WithAutoContinue(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, autoContinueKey{}, enabled)
}

// AutoContinue 返回会话级自动继续设置，未显式设置时默认开启。
func AutoContinue(ctx context.Context) bool {
	value, ok := ctx.Value(autoContinueKey{}).(bool)
	if !ok {
		return true
	}
	return value
}

func WithAssetRestriction(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, assetRestrictionKey{}, enabled)
}

// AssetRestrictionEnabled 返回会话级资产限制设置，未显式设置时默认开启。
func AssetRestrictionEnabled(ctx context.Context) bool {
	value, ok := ctx.Value(assetRestrictionKey{}).(bool)
	if !ok {
		return true
	}
	return value
}
