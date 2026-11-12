package agent

import (
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type modelIterationBudgetState struct {
	mu        sync.Mutex
	limit     int
	warnAt    int
	calls     int
	warned    bool
	exhausted bool
}

type modelIterationBudget struct {
	inner model.ToolCallingChatModel
	state *modelIterationBudgetState
}

func newModelIterationBudget(limit int) *modelIterationBudgetState {
	warnAt := 0
	if limit > 0 {
		reserve := max(1, int(math.Ceil(float64(limit)*0.02)))
		warnAt = limit - reserve
		if warnAt < 1 {
			warnAt = 1
		}
	}
	return &modelIterationBudgetState{
		limit:  limit,
		warnAt: warnAt,
	}
}

func (s *modelIterationBudgetState) IsExhausted() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exhausted
}

func wrapModelIterationBudget(
	inner model.ToolCallingChatModel,
	state *modelIterationBudgetState,
) model.ToolCallingChatModel {
	if inner == nil || state == nil || state.limit <= 0 {
		return inner
	}
	return &modelIterationBudget{inner: inner, state: state}
}

func (m *modelIterationBudget) WithTools(
	tools []*schema.ToolInfo,
) (model.ToolCallingChatModel, error) {
	inner, err := m.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &modelIterationBudget{inner: inner, state: m.state}, nil
}

func (m *modelIterationBudget) Generate(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.Message, error) {
	messages, err := m.prepare(input)
	if err != nil {
		return nil, err
	}
	return m.inner.Generate(ctx, messages, opts...)
}

func (m *modelIterationBudget) Stream(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	messages, err := m.prepare(input)
	if err != nil {
		return nil, err
	}
	return m.inner.Stream(ctx, messages, opts...)
}

func (m *modelIterationBudget) prepare(
	input []*schema.Message,
) ([]*schema.Message, error) {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	if m.state.calls >= m.state.limit {
		m.state.exhausted = true
		return nil, fmt.Errorf("%w: Agent iteration budget exhausted", adk.ErrExceedMaxIterations)
	}
	m.state.calls++
	if m.state.warned || m.state.warnAt <= 0 || m.state.calls < m.state.warnAt {
		return input, nil
	}
	m.state.warned = true
	remaining := m.state.limit - m.state.calls
	warning := fmt.Sprintf(
		"【系统预算提醒】本次 Agent 迭代预算仅剩 %d 轮（已使用 %d/%d）。立即停止扩展和低价值尝试，开始统计当前已完成工作、已验证结论、关键证据、未完成项和阻塞原因；在不调用新工具的前提下尽快给出可交付总结并结束任务。",
		remaining,
		m.state.calls,
		m.state.limit,
	)
	messages := make([]*schema.Message, 0, len(input)+1)
	messages = append(messages, input...)
	messages = append(messages, schema.UserMessage(warning))
	return messages, nil
}
