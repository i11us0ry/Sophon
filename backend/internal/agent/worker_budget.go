package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/execctx"
)

type workerBudgetKey struct{}

type workerBudgetState struct {
	mu             sync.Mutex
	maxCalls       int
	calls          int
	maxCPUSeconds  float64
	usedCPUSeconds float64
	budgetToken    string
	stateCalls     map[string]int
	noProgress     map[string]time.Time
	blockedCalls   int
}

const (
	workerBlockedCallLimit   = 3
	workerNoProgressCooldown = 30 * time.Second
)

func (b *workerBudgetState) reserve(name string, arguments ...string) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxCalls > 0 && b.calls >= b.maxCalls {
		return fmt.Errorf("Worker 工具调用预算已耗尽（%d/%d），禁止继续调用工具，请立即总结当前成果", b.calls, b.maxCalls)
	}
	if b.maxCPUSeconds > 0 && b.usedCPUSeconds >= b.maxCPUSeconds {
		return fmt.Errorf(
			"Worker CPU 预算已耗尽（%.3f/%.3f 秒），禁止继续调用工具，请立即总结当前成果",
			b.usedCPUSeconds,
			b.maxCPUSeconds,
		)
	}
	if err := b.reserveStateQueryLocked(name, arguments...); err != nil {
		return err
	}
	b.calls++
	return nil
}

func (b *workerBudgetState) reserveStateQueryLocked(name string, arguments ...string) error {
	if !isWorkerStateReadTool(name) {
		return nil
	}
	if b.noProgress == nil {
		b.noProgress = map[string]time.Time{}
	}
	rawArguments := ""
	if len(arguments) > 0 {
		rawArguments = arguments[0]
	}
	key := workerStateQueryKey(name, rawArguments)
	if markedAt, ok := b.noProgress[key]; ok {
		if time.Since(markedAt) < workerNoProgressCooldown {
			return fmt.Errorf("状态查询 %s 已返回无进展结果，禁止重复；请根据已有结果改道或立即总结", name)
		}
		delete(b.noProgress, key)
	}
	if b.stateCalls == nil {
		b.stateCalls = map[string]int{}
	}
	b.stateCalls[key]++
	if b.stateCalls[key] > 2 {
		return fmt.Errorf("同一状态查询 %s 已连续重复 %d 次，禁止再次原样调用；请修改参数、执行动作或总结", name, b.stateCalls[key])
	}
	return nil
}

func workerStateQueryKey(name string, rawArguments string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "project_list" {
		var request struct {
			Resource string `json:"resource"`
		}
		_ = json.Unmarshal([]byte(strings.TrimSpace(rawArguments)), &request)
		return name + "\x00resource:" + strings.ToLower(strings.TrimSpace(request.Resource))
	}
	if name == "project_next_targets" {
		return name
	}
	return name + "\x00" + hashedToolArguments(rawArguments)
}

func (b *workerBudgetState) noteToolResult(name string, rawArguments string, result string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	noProgress := workerNoProgressToolResult(name, result)
	if isTurnWriteTool(name) && !noProgress {
		b.stateCalls = nil
		b.noProgress = nil
		b.blockedCalls = 0
	}
	if noProgress {
		if b.noProgress == nil {
			b.noProgress = map[string]time.Time{}
		}
		b.noProgress[workerStateQueryKey(name, rawArguments)] = time.Now()
		return
	}
	b.blockedCalls = 0
}

func (b *workerBudgetState) noteBlockedCall() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blockedCalls++
	return b.blockedCalls
}

func isWorkerStateReadTool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "project_list", "project_get", "project_next_targets", "project_next_assets", "project_asset_closeout", "project_graph_overview",
		"project_list_hypotheses", "planner_todo_list":
		return true
	default:
		return false
	}
}

func workerNoProgressToolResult(name string, result string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "project_list":
		return strings.Contains(result, "当前项目没有匹配的资产。") ||
			strings.Contains(result, "当前项目还没有记录任何事实。")
	case "project_next_targets":
		return strings.Contains(result, "资产观测覆盖 0/0")
	case "project_plan_hypotheses":
		return strings.Contains(result, "测试假设已规划：写入 0 个")
	case "project_add_intent":
		return strings.Contains(result, "活跃数量已达到上限")
	case "project_list_hypotheses":
		return strings.Contains(result, "当前项目没有待处理的测试假设。")
	default:
		return false
	}
}

func (b *workerBudgetState) recordCPUUsage(result string) {
	if b == nil {
		return
	}
	seconds := parseWorkerCPUUsage(result, b.budgetToken)
	if seconds <= 0 {
		return
	}
	b.mu.Lock()
	b.usedCPUSeconds += seconds
	b.mu.Unlock()
}

func (b *workerBudgetState) remainingCPUSeconds() float64 {
	if b == nil || b.maxCPUSeconds <= 0 {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.maxCPUSeconds - b.usedCPUSeconds
	if remaining < 0 {
		return 0
	}
	return remaining
}

func parseWorkerCPUUsage(result, token string) float64 {
	token = strings.TrimSpace(token)
	if token == "" {
		return 0
	}
	pattern := regexp.MustCompile(
		`(?m)\[sophon budget:` + regexp.QuoteMeta(token) + `\] cpu_seconds=([0-9]+(?:\.[0-9]+)?)`,
	)
	matches := pattern.FindAllStringSubmatch(result, -1)
	if len(matches) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(matches[len(matches)-1][1], 64)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func withWorkerBudget(
	ctx context.Context,
	cfg config.Config,
	_ context.CancelFunc,
) context.Context {
	state := &workerBudgetState{
		maxCalls:      cfg.AgentSubagentMaxToolCalls,
		maxCPUSeconds: float64(cfg.AgentSubagentMaxCPUSeconds),
		budgetToken:   randomID(),
	}
	return context.WithValue(ctx, workerBudgetKey{}, state)
}

func workerBudgetFromContext(ctx context.Context) *workerBudgetState {
	state, _ := ctx.Value(workerBudgetKey{}).(*workerBudgetState)
	return state
}

type workerBudgetedTool struct {
	inner tool.BaseTool
	name  string
}

func wrapWorkerBudgetTools(ctx context.Context, items []tool.BaseTool) []tool.BaseTool {
	_, worker := execctx.Subagent(ctx)
	if !worker {
		return items
	}
	wrapped := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		toolInfo, err := item.Info(ctx)
		if err != nil || toolInfo == nil {
			continue
		}
		wrapped = append(wrapped, &workerBudgetedTool{
			inner: item,
			name:  strings.TrimSpace(toolInfo.Name),
		})
	}
	return wrapped
}

func (t *workerBudgetedTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.inner.Info(ctx)
}

func (t *workerBudgetedTool) MCPServerName() string {
	if named, ok := t.inner.(serverNamedTool); ok {
		return named.MCPServerName()
	}
	return ""
}

func (t *workerBudgetedTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	options ...tool.Option,
) (string, error) {
	control := workerControlFromContext(ctx)
	if control.isStopped() {
		return "", context.Canceled
	}
	if steer := workerSteerMessage(control.takeSteer()); steer != "" {
		return renderWorkerBlockedResult(t.name, steer, "plannerSteer=true"), nil
	}
	budget := workerBudgetFromContext(ctx)
	if err := budget.reserve(t.name, argumentsInJSON); err != nil {
		if budget.noteBlockedCall() >= workerBlockedCallLimit {
			return "", context.Canceled
		}
		marker := "workerNoProgressCircuitOpen=true"
		if strings.Contains(err.Error(), "预算已耗尽") {
			marker = "workerBudgetBlocked=true"
		}
		return renderWorkerBlockedResult(t.name, err.Error(), marker), nil
	}
	result, err := invokeTool(ctx, t.inner, argumentsInJSON, options...)
	budget.recordCPUUsage(result)
	if err == nil {
		budget.noteToolResult(t.name, argumentsInJSON, result)
	}
	return result, err
}

func renderWorkerBlockedResult(toolName, detail, marker string) string {
	return renderToolError(
		toolName,
		toolErrorPolicy,
		strings.TrimSpace(detail)+"\n"+strings.TrimSpace(marker)+"\ntoolExecuted=false",
		false,
		[]string{"根据已有结果继续下一步，不要重复同一调用；必要时立即总结当前成果"},
	)
}

func (s *Service) workerBudgetGuidance() string {
	cfg := s.configSnapshot()
	calls := cfg.AgentSubagentMaxToolCalls
	callsText := "不限"
	if calls > 0 {
		callsText = fmt.Sprintf("%d 次", calls)
	}
	duration := cfg.AgentSubagentMaxDuration
	if duration <= 0 {
		duration = 1800
	}
	cpuSeconds := cfg.AgentSubagentMaxCPUSeconds
	if cpuSeconds <= 0 {
		cpuSeconds = 900
	}
	processes := cfg.AgentSubagentMaxProcesses
	if processes <= 0 {
		processes = 8
	}
	return fmt.Sprintf(
		"\n\n## 强制执行预算\n"+
			"- 技能清单仅作启发式参考，不是必读前置，也不是漏洞覆盖上限。\n"+
			"- 先按目标、入口、数据流、Sink、参数化状态和证据推进；仅在没有成果、成果不理想、没有下一步思路或方向停滞时，按需读取 1-2 个最相关技能。\n"+
			"- 工具调用上限：%s；实际耗时上限：%d 秒。\n"+
			"- 单个受限进程组 CPU 上限：%d 秒；进程数上限：%d。\n"+
			"- 批量或长扫描必须使用 job(action=start) 分步执行；禁止 nohup、setsid、disown 或 shell 后台 &。\n"+
			"- 每批最多 50 个程序集；达到命中数、时间或 CPU 预算后立即停止并写回结果。\n",
		callsText,
		duration,
		cpuSeconds,
		processes,
	)
}
