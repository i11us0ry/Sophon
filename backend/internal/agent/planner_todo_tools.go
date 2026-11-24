package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"sophon/internal/database"
	"sophon/internal/execctx"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	plannerTodoListToolName   = "planner_todo_list"
	plannerTodoUpdateToolName = "planner_todo_update"
)

func newPlannerTodoTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{
		&jsonTool{
			name: plannerTodoListToolName,
			desc: "查看当前 Planner 跨唤醒持久化的串行利用链待办。",
			run: func(ctx context.Context, _ string) (string, error) {
				conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
				items, err := service.db.ListAgentPlannerTodos(ctx, conversationID)
				if err != nil {
					return "", err
				}
				encoded, _ := json.Marshal(map[string]interface{}{"items": items})
				return string(encoded), nil
			},
		},
		&jsonTool{
			name: plannerTodoUpdateToolName,
			desc: "整体更新 Planner 串行利用链待办；用于跨 Planner 唤醒保留步骤状态。",
			params: map[string]*schema.ParameterInfo{
				"todos": {
					Type:     schema.Array,
					Desc:     "待办数组，每项包含 content/status/sourceIntentId",
					Required: true,
				},
			},
			run: func(ctx context.Context, raw string) (string, error) {
				var request struct {
					Todos []struct {
						Content        string `json:"content"`
						Status         string `json:"status"`
						SourceIntentID string `json:"sourceIntentId"`
					} `json:"todos"`
				}
				if err := decodeToolArgs(raw, &request); err != nil {
					return "", err
				}
				items := make([]database.AgentPlannerTodo, 0, len(request.Todos))
				for _, item := range request.Todos {
					content := strings.TrimSpace(item.Content)
					if content == "" {
						continue
					}
					items = append(items, database.AgentPlannerTodo{
						Content:        content,
						Status:         item.Status,
						SourceIntentID: item.SourceIntentID,
					})
				}
				if len(items) == 0 && len(request.Todos) > 0 {
					return "", fmt.Errorf("todos 中没有有效 content")
				}
				saved, err := service.db.ReplaceAgentPlannerTodos(
					ctx,
					execctx.ConversationID(ctx),
					execctx.ProjectID(ctx),
					items,
				)
				if err != nil {
					return "", err
				}
				encoded, _ := json.Marshal(map[string]interface{}{"items": saved})
				return string(encoded), nil
			},
		},
	}
}

func renderPlannerTodos(items []database.AgentPlannerTodo) string {
	if len(items) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("\n\n【跨唤醒 Planner Todo】\n")
	for _, item := range items {
		mark := "☐"
		switch item.Status {
		case database.PlannerTodoInProgress:
			mark = "▶"
		case database.PlannerTodoCompleted:
			mark = "✔"
		}
		builder.WriteString(mark)
		builder.WriteString(" ")
		builder.WriteString(item.Content)
		if item.SourceIntentID != "" {
			builder.WriteString("（来源意图 ")
			builder.WriteString(item.SourceIntentID)
			builder.WriteString("）")
		}
		builder.WriteString("\n")
	}
	builder.WriteString("只推进前置条件已满足的步骤，完成或失败后及时更新 Todo。")
	return builder.String()
}
