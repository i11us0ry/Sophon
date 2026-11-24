package agent

import (
	"context"
	"encoding/json"
	"strings"

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
	input = sanitizeToolCallArguments(input)
	return m.inner.Generate(ctx, withTokenBudgetWarning(ctx, input), opts...)
}

func (m *modelTokenBudget) Stream(
	ctx context.Context,
	input []*schema.Message,
	opts ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	input = sanitizeToolCallArguments(input)
	return m.inner.Stream(ctx, withTokenBudgetWarning(ctx, input), opts...)
}

func sanitizeToolCallArguments(input []*schema.Message) []*schema.Message {
	var output []*schema.Message
	for index, message := range input {
		if message == nil || len(message.ToolCalls) == 0 {
			continue
		}
		calls := append([]schema.ToolCall(nil), message.ToolCalls...)
		changed := false
		for callIndex := range calls {
			normalized := normalizeToolCallArguments(calls[callIndex].Function.Arguments)
			if normalized == calls[callIndex].Function.Arguments {
				continue
			}
			calls[callIndex].Function.Arguments = normalized
			changed = true
		}
		if !changed {
			continue
		}
		if output == nil {
			output = append([]*schema.Message(nil), input...)
		}
		cloned := *message
		cloned.ToolCalls = calls
		output[index] = &cloned
	}
	if output == nil {
		return input
	}
	return output
}

func normalizeToolCallArguments(arguments string) string {
	arguments = strings.TrimSpace(arguments)
	if arguments == "" || !strings.HasPrefix(arguments, "{") {
		return "{}"
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(arguments), &object); err != nil || object == nil {
		return "{}"
	}
	return arguments
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
