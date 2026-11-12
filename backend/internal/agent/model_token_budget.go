package agent

import (
	"context"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type modelTokenBudget struct {
	inner model.ToolCallingChatModel
}

func wrapModelTokenBudget(inner model.ToolCallingChatModel) model.ToolCallingChatModel {
	if inner == nil {
		return nil
	}
	return &modelTokenBudget{inner: inner}
}

func (m *modelTokenBudget) WithTools(
	tools []*schema.ToolInfo,
) (model.ToolCallingChatModel, error) {
	inner, err := m.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &modelTokenBudget{inner: inner}, nil
}

func (m *modelTokenBudget) Generate(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.Message, error) {
	return m.inner.Generate(ctx, withTokenBudgetWarning(ctx, input), opts...)
}

func (m *modelTokenBudget) Stream(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return m.inner.Stream(ctx, withTokenBudgetWarning(ctx, input), opts...)
}

func withTokenBudgetWarning(ctx context.Context, input []*schema.Message) []*schema.Message {
	warning := runTokenBudgetFromContext(ctx).warningMessage()
	if warning == "" {
		return input
	}
	messages := make([]*schema.Message, 0, len(input)+1)
	messages = append(messages, input...)
	messages = append(messages, schema.UserMessage(warning))
	return messages
}
