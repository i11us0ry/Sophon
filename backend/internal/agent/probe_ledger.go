package agent

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	probeLedgerLookback     = 90 * time.Minute
	probeLedgerFetchLimit   = 200
	probeLedgerDisplayLimit = 10
	probeLedgerHostLimit    = 4
	probeLedgerPathLimit    = 6
)

var (
	probeHostPattern   = regexp.MustCompile(`(?i)\b([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+(com|cn|net|org|cloud|io|co|local)\b(:[0-9]{1,5})?`)
	probeIPPattern     = regexp.MustCompile(`\b([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?\b`)
	probeMethodPattern = regexp.MustCompile(`(?i)(-X|--request(=|[[:space:]]+))[[:space:]]*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)`)
	probePathPattern   = regexp.MustCompile(`(^|[[:space:]"'=(])(/[A-Za-z0-9._~%/+@-]+)`)
	probeURLPattern    = regexp.MustCompile(`(?i)https?://[^[:space:]"'<>]+`)
)

type probeTargetInfo struct {
	hosts   []string
	methods []string
	paths   []string
}

type probeLedgerGroup struct {
	key       string
	label     string
	completed int
	failed    int
	running   int
	lastAt    time.Time
}

func collectProbeStrings(value interface{}, target *strings.Builder) {
	switch item := value.(type) {
	case string:
		target.WriteString(item)
		target.WriteByte('\n')
	case []interface{}:
		for _, child := range item {
			collectProbeStrings(child, target)
		}
	case []string:
		for _, child := range item {
			collectProbeStrings(child, target)
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectProbeStrings(item[key], target)
		}
	}
}

func extractProbeTarget(args map[string]interface{}) probeTargetInfo {
	var text strings.Builder
	collectProbeStrings(args, &text)
	content := text.String()
	hosts := map[string]bool{}
	paths := map[string]bool{}
	methods := map[string]bool{}

	for _, candidate := range probeHostPattern.FindAllString(content, -1) {
		hosts[strings.ToLower(strings.TrimSpace(candidate))] = true
	}
	for _, candidate := range probeIPPattern.FindAllString(content, -1) {
		hosts[strings.ToLower(strings.TrimSpace(candidate))] = true
	}
	for _, rawURL := range probeURLPattern.FindAllString(content, -1) {
		parsed, err := url.Parse(strings.TrimRight(rawURL, ".,;)"))
		if err != nil || strings.TrimSpace(parsed.Hostname()) == "" {
			continue
		}
		if relevantProbePath(parsed.Path) {
			paths[parsed.Path] = true
		}
		host := strings.ToLower(parsed.Hostname())
		if strings.HasPrefix(host, "$") || !strings.Contains(host, ".") {
			continue
		}
		if parsed.Port() != "" {
			host += ":" + parsed.Port()
		}
		hosts[host] = true
	}
	for _, match := range probePathPattern.FindAllStringSubmatch(content, -1) {
		if len(match) < 3 || !relevantProbePath(match[2]) {
			continue
		}
		paths[strings.SplitN(match[2], "?", 2)[0]] = true
	}
	for _, match := range probeMethodPattern.FindAllStringSubmatch(content, -1) {
		if len(match) >= 4 && strings.TrimSpace(match[3]) != "" {
			methods[strings.ToUpper(strings.TrimSpace(match[3]))] = true
		}
	}
	if len(methods) == 0 && strings.Contains(strings.ToLower(content), "curl") {
		lower := strings.ToLower(content)
		if strings.Contains(lower, " -d ") || strings.Contains(lower, "--data") {
			methods["POST"] = true
		} else {
			methods["GET"] = true
		}
	}

	return probeTargetInfo{
		hosts:   limitedSortedKeys(hosts, probeLedgerHostLimit),
		methods: limitedSortedKeys(methods, 3),
		paths:   limitedSortedKeys(paths, probeLedgerPathLimit),
	}
}

func relevantProbePath(path string) bool {
	path = strings.TrimSpace(strings.SplitN(path, "?", 2)[0])
	if path == "" || path == "/" {
		return false
	}
	lower := strings.ToLower(path)
	for _, prefix := range []string{"/tmp/", "/var/", "/etc/", "/usr/", "/opt/", "/home/", "/root/", "/dev/", "/proc/"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	if strings.Count(path, "/") >= 2 {
		return true
	}
	for _, prefix := range []string{
		"/api", "/rc_", "/fof", "/user", "/auth", "/oa/", "/gateway", "/falcon",
		"/channel", "/sso", "/login", "/permission", "/system", "/admin", "/upload", "/download",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func limitedSortedKeys(values map[string]bool, limit int) []string {
	items := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			items = append(items, value)
		}
	}
	sort.Strings(items)
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func probeSemanticKey(args map[string]interface{}) string {
	target := extractProbeTarget(args)
	if len(target.hosts) == 0 && len(target.paths) == 0 {
		return ""
	}
	return strings.Join([]string{
		"hosts=" + strings.Join(target.hosts, ","),
		"methods=" + strings.Join(target.methods, ","),
		"paths=" + strings.Join(target.paths, ","),
	}, "|")
}

func probeTargetLabel(args map[string]interface{}) string {
	target := extractProbeTarget(args)
	parts := make([]string, 0, 3)
	if len(target.methods) > 0 {
		parts = append(parts, strings.Join(target.methods, "/"))
	}
	if len(target.hosts) > 0 {
		parts = append(parts, strings.Join(target.hosts, ", "))
	}
	label := strings.Join(parts, " ")
	if len(target.paths) > 0 {
		label += " -> " + strings.Join(target.paths, ", ")
	}
	return strings.TrimSpace(label)
}

func buildProbeLedger(executions []database.ToolExecution, limit int) []probeLedgerGroup {
	if limit <= 0 {
		limit = probeLedgerDisplayLimit
	}
	byKey := map[string]*probeLedgerGroup{}
	order := make([]string, 0)
	for _, execution := range executions {
		key := probeSemanticKey(execution.Arguments)
		if key == "" {
			continue
		}
		group := byKey[key]
		if group == nil {
			group = &probeLedgerGroup{
				key:    key,
				label:  probeTargetLabel(execution.Arguments),
				lastAt: execution.StartedAt,
			}
			byKey[key] = group
			order = append(order, key)
		}
		switch strings.ToLower(strings.TrimSpace(execution.Status)) {
		case "completed":
			group.completed++
		case "failed":
			group.failed++
		default:
			group.running++
		}
	}
	items := make([]probeLedgerGroup, 0, len(order))
	for _, key := range order {
		items = append(items, *byKey[key])
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].lastAt.After(items[j].lastAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func (s *Service) recentProbeExecutions(ctx context.Context, conversationID string) []database.ToolExecution {
	if s == nil || s.db == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	items, err := s.db.ListRecentProbeExecutions(
		ctx,
		conversationID,
		time.Now().UTC().Add(-probeLedgerLookback),
		probeLedgerFetchLimit,
	)
	if err != nil {
		return nil
	}
	return items
}

func (s *Service) recentProbeHosts(ctx context.Context, conversationID string) map[string]bool {
	result := map[string]bool{}
	for _, execution := range s.recentProbeExecutions(ctx, conversationID) {
		for _, host := range extractProbeTarget(execution.Arguments).hosts {
			result[host] = true
		}
	}
	return result
}

func recentProbeAnnotation(label string, hosts map[string]bool) string {
	if len(hosts) == 0 {
		return ""
	}
	lowerLabel := strings.ToLower(label)
	for host := range hosts {
		if strings.Contains(lowerLabel, host) {
			return "；最近已探测但尚未闭环，先写回测试结果，不要盲目重扫"
		}
	}
	return ""
}

func formatProbeLedger(groups []probeLedgerGroup) string {
	if len(groups) == 0 {
		return "- 无\n"
	}
	var builder strings.Builder
	for _, group := range groups {
		statuses := make([]string, 0, 3)
		if group.completed > 0 {
			statuses = append(statuses, fmt.Sprintf("completed×%d", group.completed))
		}
		if group.failed > 0 {
			statuses = append(statuses, fmt.Sprintf("failed×%d", group.failed))
		}
		if group.running > 0 {
			statuses = append(statuses, fmt.Sprintf("running×%d", group.running))
		}
		builder.WriteString(fmt.Sprintf(
			"- %s %s：%s\n",
			group.lastAt.Format("15:04"),
			strings.Join(statuses, "/"),
			truncateProjectText(group.label, situationTextRune*2),
		))
	}
	return builder.String()
}

func currentConversationID(ctx context.Context) string {
	return strings.TrimSpace(execctx.ConversationID(ctx))
}
