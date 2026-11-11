package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/observability"
)

// observedTool 为每次工具调用产生 started/completed/failed 事件。
// 事件只包含工具名、耗时、成败与错误分类，不写入参数与输出。
type observedTool struct {
	service *Service
	name    string
	inner   tool.BaseTool
}

func (s *Service) observeTools(items []tool.BaseTool) []tool.BaseTool {
	if s == nil {
		return items
	}
	observed := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if _, ok := item.(tool.InvokableTool); !ok {
			observed = append(observed, item)
			continue
		}
		name := ""
		if info, err := item.Info(context.Background()); err == nil && info != nil {
			name = strings.TrimSpace(info.Name)
		}
		observed = append(observed, &observedTool{service: s, name: name, inner: item})
	}
	return observed
}

func (t *observedTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.inner.Info(ctx)
}

// MCPServerName 转发 MCP 服务名，保证工具清单能标明直连工具的来源服务。
func (t *observedTool) MCPServerName() string {
	if named, ok := t.inner.(serverNamedTool); ok {
		return named.MCPServerName()
	}
	return ""
}

func (t *observedTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	options ...tool.Option,
) (string, error) {
	cacheKind := turnToolCacheKind(t.name, argumentsInJSON)
	if cached, ok := t.service.lookupTurnToolCache(ctx, t.name, cacheKind); ok {
		return cached, nil
	}
	if previous, ok := t.service.lookupRecentProbeExecution(ctx, t.name, argumentsInJSON); ok {
		event := agentEvent(ctx, observability.TypeToolCompleted)
		event.ToolName = t.name
		event.ServerName = t.serverName(ctx)
		event.Success = observability.Bool(true)
		event.Detail = "duplicate_probe_reused"
		t.service.emit(event)
		return formatReusedProbeResult(previous), nil
	}
	startedAt := time.Now()
	if t.service.emitter() == nil {
		result, err := invokeTool(ctx, t.inner, argumentsInJSON, options...)
		if err == nil {
			if invalidatesTurnReadCache(t.name) {
				t.service.invalidateTurnReadCache(ctx)
			}
			t.service.storeTurnToolCache(ctx, t.name, cacheKind, result)
			result = t.withEvidenceFooter(ctx, argumentsInJSON, result, startedAt)
		}
		return result, err
	}
	startEvent := agentEvent(ctx, observability.TypeToolStarted)
	startEvent.ToolName = t.name
	startEvent.ServerName = t.serverName(ctx)
	t.service.emit(startEvent)

	result, err := invokeTool(ctx, t.inner, argumentsInJSON, options...)
	if err == nil {
		if invalidatesTurnReadCache(t.name) {
			t.service.invalidateTurnReadCache(ctx)
		}
		t.service.storeTurnToolCache(ctx, t.name, cacheKind, result)
		result = t.withEvidenceFooter(ctx, argumentsInJSON, result, startedAt)
	}
	duration := time.Since(startedAt).Milliseconds()
	event := agentEvent(ctx, observability.TypeToolCompleted)
	event.ToolName = t.name
	event.ServerName = startEvent.ServerName
	event.DurationMS = duration
	if err != nil {
		event.EventType = observability.TypeToolFailed
		event.Success = observability.Bool(false)
		event.ErrorCategory = observability.ErrorCategory(err.Error())
		event.Detail = truncateEventDetail(err.Error())
	} else {
		event.Success = observability.Bool(true)
	}
	t.service.emit(event)
	return result, err
}

func (t *observedTool) withEvidenceFooter(
	ctx context.Context,
	rawArguments string,
	result string,
	startedAt time.Time,
) string {
	if t == nil || t.service == nil || t.service.db == nil || !isProbeReplayTool(t.name) {
		return result
	}
	fingerprint := database.ToolExecutionFingerprintFromJSON(rawArguments)
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if fingerprint == "" || conversationID == "" {
		return result
	}
	item, err := t.service.db.FindRecentCompletedToolExecution(
		ctx,
		conversationID,
		t.name,
		fingerprint,
		startedAt.Add(-time.Second),
	)
	if err != nil || item == nil || item.ID == "" {
		return result
	}
	return result + "\n\n[sophon evidence_ref] tool:" + item.ID
}

func formatReusedProbeResult(previous *database.ToolExecution) string {
	if previous == nil {
		return "检测到重复探测，但未找到可复用的历史结果。请修改参数后重试。"
	}
	result := strings.TrimSpace(previous.Result)
	if result == "" {
		result = "（上次执行没有文本输出）"
	}
	result = truncateRunes(result, 6000)
	return fmt.Sprintf(
		"[重复探测已拦截]\n相同命令已于 %s 成功完成，本次未再次发起执行。\n"+
			"可复用证据：tool:%s\n"+
			"如需强制重测，请修改命令参数、凭据或目标路径。\n\n上次结果：\n%s",
		previous.StartedAt.Format("2006-01-02 15:04:05"),
		previous.ID,
		result,
	)
}

func (t *observedTool) serverName(ctx context.Context) string {
	if t.service == nil || t.service.registry == nil {
		return ""
	}
	return t.service.registry.serverOf(t.name)
}

// truncateEventDetail 限制事件中的错误说明长度，避免把工具输出写进事件流。
func truncateEventDetail(message string) string {
	return truncateRunes(strings.TrimSpace(message), 200)
}
