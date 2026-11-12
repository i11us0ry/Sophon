package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type recordingModel struct {
	inputs [][]*schema.Message
}

func (m *recordingModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *recordingModel) Generate(
	_ context.Context,
	input []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	m.inputs = append(m.inputs, append([]*schema.Message(nil), input...))
	return schema.AssistantMessage("ok", nil), nil
}

func (m *recordingModel) Stream(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	message, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{message}), nil
}

func TestModelIterationBudgetWarnsOnceAtTwoPercentRemaining(t *testing.T) {
	base := &recordingModel{}
	budget := wrapModelIterationBudget(base, newModelIterationBudget(500))
	ctx := context.Background()

	for i := 1; i <= 490; i++ {
		if _, err := budget.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
			t.Fatalf("第 %d 次调用不应失败: %v", i, err)
		}
	}
	if got := inputContains(base.inputs[488], "系统预算提醒"); got {
		t.Fatal("第 489 次调用不应提前提醒")
	}
	if !inputContains(base.inputs[489], "系统预算提醒") ||
		!inputContains(base.inputs[489], "仅剩 10 轮") {
		t.Fatal("第 490 次调用应提醒剩余 2% 预算")
	}

	if _, err := budget.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
		t.Fatalf("第 491 次调用不应失败: %v", err)
	}
	if inputContains(base.inputs[490], "系统预算提醒") {
		t.Fatal("预算提醒只应注入一次")
	}
	for i := 492; i <= 500; i++ {
		if _, err := budget.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); err != nil {
			t.Fatalf("第 %d 次调用不应失败: %v", i, err)
		}
	}
	if _, err := budget.Generate(ctx, []*schema.Message{schema.UserMessage("continue")}); !errors.Is(err, adk.ErrExceedMaxIterations) {
		t.Fatalf("超过预算应返回最大迭代错误，实际 %v", err)
	}
}

func TestModelIterationBudgetWithToolsSharesState(t *testing.T) {
	state := newModelIterationBudget(2)
	base := &recordingModel{}
	first := wrapModelIterationBudget(base, state)
	second, err := first.WithTools(nil)
	if err != nil {
		t.Fatalf("绑定工具失败: %v", err)
	}

	if _, err := first.Generate(context.Background(), []*schema.Message{schema.UserMessage("first")}); err != nil {
		t.Fatalf("第一次调用失败: %v", err)
	}
	if _, err := second.Generate(context.Background(), []*schema.Message{schema.UserMessage("second")}); err != nil {
		t.Fatalf("第二次调用失败: %v", err)
	}
	if _, err := second.Generate(context.Background(), []*schema.Message{schema.UserMessage("third")}); !errors.Is(err, adk.ErrExceedMaxIterations) {
		t.Fatalf("WithTools 后应共享预算，实际 %v", err)
	}
}

func inputContains(input []*schema.Message, want string) bool {
	for _, message := range input {
		if message != nil && strings.Contains(message.Content, want) {
			return true
		}
	}
	return false
}
