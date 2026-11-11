// Package intercept implements user-configurable tool-call interception rules.
// Rules are evaluated in priority order (highest first); the first match wins.
package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"sophon/internal/database"
)

const (
	ActionAllow = "allow"
	ActionAsk   = "ask"
	ActionDeny  = "deny"

	TargetToolName  = "tool_name"
	TargetToolInput = "tool_input"

	MatchRegex  = "regex"
	MatchString = "string"
)

type Decision struct {
	Action string
	Rule   database.InterceptRule
	Reason string
}

func NormalizeAction(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ActionAllow:
		return ActionAllow, true
	case ActionAsk, "approval", "require_approval":
		return ActionAsk, true
	case ActionDeny, "block":
		return ActionDeny, true
	default:
		return "", false
	}
}

func NormalizeTarget(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case TargetToolName:
		return TargetToolName, true
	case TargetToolInput, "arguments", "args":
		return TargetToolInput, true
	default:
		return "", false
	}
}

func NormalizeMatchType(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case MatchRegex:
		return MatchRegex, true
	case MatchString, "contains":
		return MatchString, true
	default:
		return "", false
	}
}

// ValidateRule normalizes and validates a rule before persistence.
func ValidateRule(rule *database.InterceptRule) error {
	if rule == nil {
		return fmt.Errorf("规则不能为空")
	}
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	if len([]rune(rule.Name)) > 120 {
		return fmt.Errorf("规则名称不能超过 120 个字符")
	}
	if rule.Priority < 0 || rule.Priority > 10000 {
		return fmt.Errorf("优先级需在 0-10000 之间")
	}
	target, ok := NormalizeTarget(rule.MatchTarget)
	if !ok {
		return fmt.Errorf("匹配目标必须是 tool_name 或 tool_input")
	}
	rule.MatchTarget = target
	matchType, ok := NormalizeMatchType(rule.MatchType)
	if !ok {
		return fmt.Errorf("匹配类型必须是 regex 或 string")
	}
	rule.MatchType = matchType
	action, ok := NormalizeAction(rule.Action)
	if !ok {
		return fmt.Errorf("动作必须是 allow、ask 或 deny")
	}
	rule.Action = action
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	if rule.Pattern == "" {
		return fmt.Errorf("匹配 Pattern 不能为空")
	}
	if len([]rune(rule.Pattern)) > 4000 {
		return fmt.Errorf("匹配 Pattern 不能超过 4000 个字符")
	}
	rule.Message = strings.TrimSpace(rule.Message)
	if len([]rune(rule.Message)) > 2000 {
		return fmt.Errorf("命中提示不能超过 2000 个字符")
	}
	if rule.MatchType == MatchRegex {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("正则不合法: %v", err)
		}
	}
	return nil
}

// Evaluate returns the first matching enabled rule, or nil when none match.
func Evaluate(
	ctx context.Context,
	db *database.DB,
	toolName string,
	args map[string]interface{},
) (*Decision, error) {
	if db == nil {
		return nil, nil
	}
	rules, err := db.ListInterceptRules(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(rules, func(left, right int) bool {
		if rules[left].Priority != rules[right].Priority {
			return rules[left].Priority > rules[right].Priority
		}
		return rules[left].CreatedAt.Before(rules[right].CreatedAt)
	})
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		matched, err := ruleMatches(rule, toolName, args)
		if err != nil {
			continue // invalid legacy regex is skipped rather than breaking every tool call
		}
		if !matched {
			continue
		}
		reason := strings.TrimSpace(rule.Message)
		if reason == "" {
			reason = "命中拦截规则：" + rule.Name
		}
		return &Decision{Action: rule.Action, Rule: rule, Reason: reason}, nil
	}
	return nil, nil
}

func TestRule(rule database.InterceptRule, toolName string, args map[string]interface{}) (bool, error) {
	if err := ValidateRule(&rule); err != nil {
		return false, err
	}
	return ruleMatches(rule, toolName, args)
}

func ruleMatches(rule database.InterceptRule, toolName string, args map[string]interface{}) (bool, error) {
	value := toolName
	if rule.MatchTarget == TargetToolInput {
		encoded, err := json.Marshal(args)
		if err != nil {
			return false, err
		}
		value = string(encoded)
	}
	switch rule.MatchType {
	case MatchRegex:
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return false, err
		}
		return re.MatchString(value), nil
	case MatchString:
		if rule.MatchTarget == TargetToolName {
			return strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(rule.Pattern)), nil
		}
		return strings.Contains(value, rule.Pattern), nil
	default:
		return false, fmt.Errorf("未知匹配类型")
	}
}
