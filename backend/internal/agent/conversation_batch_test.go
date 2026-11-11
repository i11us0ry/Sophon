package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestConversationBatchBriefingIncludesTargetAndInstruction(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	asset := database.Asset{
		ID:          "batch-asset",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "目标站",
		Kind:        "url",
		Value:       "https://batch.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	parent := database.Conversation{
		ID:          "batch-parent-agent",
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Title:       "批量任务",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	child := database.Conversation{
		ID:          "batch-child-agent",
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Title:       "目标站",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if _, _, err := service.db.CreateConversationBatch(
		ctx,
		database.ConversationBatch{
			ID:                   "batch-agent",
			OwnerUserID:          "user-1",
			ProjectID:            "project-tools",
			ParentConversationID: parent.ID,
			Title:                "批量任务",
			Instruction:          "检查授权范围内的 Web 漏洞",
			Total:                1,
			CreatedAt:            now,
			UpdatedAt:            now,
		},
		parent,
		[]database.ConversationBatchItem{{
			Asset:        asset,
			Conversation: child,
		}},
		"",
	); err != nil {
		t.Fatalf("创建批次失败: %v", err)
	}

	briefing := service.conversationBatchBriefing(ctx, child.ID, "user-1")
	for _, want := range []string{
		"https://batch.example.com",
		"批量任务",
		"检查授权范围内的 Web 漏洞",
	} {
		if !strings.Contains(briefing, want) {
			t.Fatalf("批次上下文缺少 %q: %s", want, briefing)
		}
	}
}
