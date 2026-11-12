package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudwego/eino/schema"
)

func TestModelTokenBudgetWarnsOnceAtTwoPercentRemaining(t *testing.T) {
	base := &recordingModel{}
	wrapped := wrapModelTokenBudget(base)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget := &runTokenBudget{limit: 1000, cancel: cancel}
	ctx = context.WithValue(ctx, runTokenBudgetKey{}, budget)

	_, _ = wrapped.Generate(ctx, []*schema.Message{schema.UserMessage("prepare")})
	budget.add(979)
	if _, err := wrapped.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
		t.Fatalf("预警前调用不应失败: %v", err)
	}
	if inputContains(base.inputs[len(base.inputs)-1], "系统 Token 预算提醒") {
		t.Fatal("预算剩余超过 2% 时不应提醒")
	}

	budget.add(1)
	if _, err := wrapped.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
		t.Fatalf("预警调用不应失败: %v", err)
	}
	if !inputContains(base.inputs[len(base.inputs)-1], "系统 Token 预算提醒") ||
		!inputContains(base.inputs[len(base.inputs)-1], "禁止调用新工具") {
		t.Fatal("预算剩余 2% 时应要求停止扩展并总结")
	}

	if _, err := wrapped.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
		t.Fatalf("重复调用不应失败: %v", err)
	}
	if inputContains(base.inputs[len(base.inputs)-1], "系统 Token 预算提醒") {
		t.Fatal("Token 预算提醒只应注入一次")
	}
}

func TestTokenBudgetSummaryContextIgnoresExhaustedCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	budget := &runTokenBudget{limit: 10, cancel: cancel}
	parent = context.WithValue(parent, runTokenBudgetKey{}, budget)
	budget.add(10)
	if !errors.Is(parent.Err(), context.Canceled) {
		t.Fatal("测试前置条件错误：原上下文应已被 Token 预算取消")
	}

	summaryCtx, summaryCancel := tokenBudgetSummaryContext(parent)
	defer summaryCancel()
	if summaryCtx.Err() != nil {
		t.Fatalf("总结上下文不应继承预算取消: %v", summaryCtx.Err())
	}
	if limit := runTokenBudgetFromContext(summaryCtx).limit; limit != 0 {
		t.Fatalf("总结上下文应使用独立预算，实际 limit=%d", limit)
	}
}

func TestTokenBudgetStopsStartingAnotherSegmentAtNinetyEightPercent(t *testing.T) {
	budget := &runTokenBudget{limit: 1000}
	budget.add(979)
	if budget.shouldSynthesize() {
		t.Fatal("98% 之前不应进入收尾")
	}
	budget.add(1)
	if !budget.shouldSynthesize() {
		t.Fatal("达到 98% 后应进入收尾")
	}
}

func TestWrapModelTokenBudgetWithToolsSharesContextBudget(t *testing.T) {
	base := &recordingModel{}
	first := wrapModelTokenBudget(base)
	second, err := first.WithTools([]*schema.ToolInfo{})
	if err != nil {
		t.Fatalf("绑定工具失败: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget := &runTokenBudget{limit: 100, cancel: cancel}
	ctx = context.WithValue(ctx, runTokenBudgetKey{}, budget)
	budget.add(98)

	if _, err := second.Generate(ctx, []*schema.Message{schema.UserMessage("summarize")}); err != nil {
		t.Fatalf("Generate 调用失败: %v", err)
	}
	if !inputContains(base.inputs[len(base.inputs)-1], "系统 Token 预算提醒") {
		t.Fatal("WithTools 后仍应共享 Token 预算提醒")
	}
}
