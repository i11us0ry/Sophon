package policy

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/intercept"
)

type DecisionKind string

const (
	DecisionAllow           DecisionKind = "allow"
	DecisionRequireApproval DecisionKind = "require_approval"
	DecisionDeny            DecisionKind = "deny"
)

type Decision struct {
	Kind                DecisionKind
	EffectiveCapability Capability
	Targets             []string
	Reason              string
	MatchedRule         bool
}

type Engine struct {
	db *database.DB
}

func NewEngine(db *database.DB) *Engine {
	return &Engine{db: db}
}

// Evaluate applies project authorization first, then the first enabled rule
// from Settings > Interception. Command capability and destructive semantics
// remain delegated to those rules; authorization scope is a separate boundary.
func (e *Engine) Evaluate(
	ctx context.Context,
	projectID string,
	userID string,
	_ string,
	toolName string,
	args map[string]interface{},
) (Decision, error) {
	if e == nil || e.db == nil {
		return Decision{
			Kind:   DecisionDeny,
			Reason: "拦截设置不可用",
		}, nil
	}

	result := Decision{
		EffectiveCapability: DefaultCapability(toolName),
		Targets:             uniqueStrings(targetsForTool(toolName, args)),
		Reason:              "未命中拦截设置，按基础策略放行",
	}
	if len(result.Targets) > 0 && !authorizationScopeExempt(toolName) {
		campaignID := strings.TrimSpace(execctx.CampaignID(ctx))
		assets, err := e.db.ListProjectAssets(ctx, projectID, userID)
		if campaignID != "" {
			assets, err = e.db.ListCampaignAssets(ctx, campaignID, userID)
		}
		if err != nil {
			result.Kind = DecisionDeny
			result.Reason = "无法读取授权资产范围"
			return result, err
		}
		scope := newScope(assets)
		runScopes := []string(nil)
		if campaignID == "" {
			runScopes = execctx.AuthorizedScopes(ctx)
		}
		authorized := false
		for _, target := range result.Targets {
			if scope.Allows(target) || targetAllowedByRunScopes(target, runScopes) {
				authorized = true
				break
			}
		}
		if !authorized {
			result.Kind = DecisionDeny
			if campaignID != "" {
				result.Reason = fmt.Sprintf("目标 %s 均不在当前 Campaign 授权资产范围内", strings.Join(result.Targets, "、"))
			} else {
				result.Reason = fmt.Sprintf("目标 %s 均不在当前项目授权资产范围内", strings.Join(result.Targets, "、"))
			}
			return result, nil
		}
	}

	rule, err := intercept.Evaluate(ctx, e.db, toolName, args)
	if err != nil {
		result.Kind = DecisionDeny
		result.Reason = "读取拦截设置失败"
		return result, err
	}
	if rule == nil {
		result.Kind = DecisionAllow
		return result, nil
	}

	result.Reason = rule.Reason
	result.MatchedRule = true
	switch rule.Action {
	case intercept.ActionAllow:
		result.Kind = DecisionAllow
	case intercept.ActionAsk:
		result.Kind = DecisionRequireApproval
	case intercept.ActionDeny:
		result.Kind = DecisionDeny
	default:
		result.Kind = DecisionDeny
		result.Reason = "拦截设置包含无效动作"
	}
	return result, nil
}

// authorizationScopeExempt 仅关闭直接命令执行工具的资产范围校验；
// 拦截规则仍会正常评估。
func authorizationScopeExempt(toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if index := strings.Index(name, "__"); index >= 0 {
		name = name[index+2:]
	}
	return name == "exec" || name == "execute-python-script"
}

func targetAllowedByRunScopes(target string, scopes []string) bool {
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

// targetsForTool extracts only authorization targets. Command capability and
// destructive semantics remain fully delegated to intercept rules.
func targetsForTool(toolName string, args map[string]interface{}) []string {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "exec":
		return AnalyzeCommand(stringArg(args, "command")).Targets
	case "execute-python-script":
		workspace := strings.TrimSpace(stringArg(args, "_sophon_workspace"))
		if workspace == "" {
			workspace = strings.TrimSpace(stringArg(args, "workdir"))
		}
		return AnalyzePythonScriptInWorkspace(
			stringArg(args, "script"),
			workspace,
		).Targets
	default:
		return extractTargetsFromArgs(args)
	}
}

func extractTargetsFromArgs(args map[string]interface{}) []string {
	targets := map[string]bool{}
	var walk func(interface{})
	walk = func(value interface{}) {
		switch typed := value.(type) {
		case string:
			for _, target := range targetsFromString(typed) {
				targets[target] = true
			}
		case []interface{}:
			for _, item := range typed {
				walk(item)
			}
		case []string:
			for _, item := range typed {
				walk(item)
			}
		case map[string]interface{}:
			for key, item := range typed {
				if isTargetKey(key) {
					walk(item)
				}
			}
		}
	}
	for key, value := range args {
		if isTargetKey(key) {
			walk(value)
		}
	}
	out := make([]string, 0, len(targets))
	for target := range targets {
		out = append(out, target)
	}
	return out
}

func targetsFromString(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return []string{strings.ToLower(parsed.Hostname())}
	}
	host := value
	if isLikelyLocalPath(host) {
		return nil
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if isHostLike(host) {
		return []string{strings.ToLower(host)}
	}
	return nil
}

func isTargetKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "target", "targets", "host", "hosts", "hostname", "domain",
		"domains", "url", "urls", "ip", "ips", "endpoint", "base_url",
		"baseurl", "address", "addr":
		return true
	default:
		return false
	}
}

func stringArg(args map[string]interface{}, key string) string {
	value, _ := args[key].(string)
	return value
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
