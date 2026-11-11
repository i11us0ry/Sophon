package agent

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

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
	cancel         context.CancelFunc
}

func (b *workerBudgetState) reserve(name string) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxCalls > 0 && b.calls >= b.maxCalls {
		if b.cancel != nil {
			b.cancel()
		}
		return fmt.Errorf("Worker 工具调用预算已耗尽（%d/%d），已终止当前 Worker", b.calls, b.maxCalls)
	}
	if b.maxCPUSeconds > 0 && b.usedCPUSeconds >= b.maxCPUSeconds {
		if b.cancel != nil {
			b.cancel()
		}
		return fmt.Errorf(
			"Worker CPU 预算已耗尽（%.3f/%.3f 秒），已终止当前 Worker",
			b.usedCPUSeconds,
			b.maxCPUSeconds,
		)
	}
	b.calls++
	return nil
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
	exhausted := b.maxCPUSeconds > 0 && b.usedCPUSeconds >= b.maxCPUSeconds
	cancel := b.cancel
	b.mu.Unlock()
	if exhausted && cancel != nil {
		cancel()
	}
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
	cancel context.CancelFunc,
) context.Context {
	state := &workerBudgetState{
		maxCalls:      cfg.AgentSubagentMaxToolCalls,
		maxCPUSeconds: float64(cfg.AgentSubagentMaxCPUSeconds),
		budgetToken:   randomID(),
		cancel:        cancel,
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
	if err := workerBudgetFromContext(ctx).reserve(t.name); err != nil {
		return "", err
	}
	result, err := invokeTool(ctx, t.inner, argumentsInJSON, options...)
	workerBudgetFromContext(ctx).recordCPUUsage(result)
	return result, err
}

func (s *Service) workerBudgetGuidance() string {
	cfg := s.configSnapshot()
	calls := cfg.AgentSubagentMaxToolCalls
	if calls <= 0 {
		calls = 80
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
			"- 工具调用上限：%d 次；实际耗时上限：%d 秒。\n"+
			"- 单个受限进程组 CPU 上限：%d 秒；进程数上限：%d。\n"+
			"- 批量或长扫描必须使用 job(action=start) 分步执行；禁止 nohup、setsid、disown 或 shell 后台 &。\n"+
			"- 每批最多 50 个程序集；达到命中数、时间或 CPU 预算后立即停止并写回结果。\n",
		calls,
		duration,
		cpuSeconds,
		processes,
	)
}
