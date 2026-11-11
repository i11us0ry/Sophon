package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestEstimateTextTokensV2(t *testing.T) {
	if got := estimateTextTokensV2("   "); got != 0 {
		t.Fatalf("空白文本应为 0，实际 %d", got)
	}
	cjk := estimateTextTokensV2("你好世界")
	if cjk < 4 {
		t.Fatalf("中文应按约 1 token/字估算，实际 %d", cjk)
	}
	short := estimateTextTokensV2("测试")
	long := estimateTextTokensV2(strings.Repeat("测试", 50))
	if long <= short {
		t.Fatalf("token 估算应随文本增长：short=%d long=%d", short, long)
	}
}

func TestContextBudgetTokensPrefersExplicitTokens(t *testing.T) {
	service := &Service{cfg: config.Config{
		AgentContextMaxChars:  24000,
		AgentContextMaxTokens: 64000,
	}}
	if got := service.contextBudgetTokens(); got != 64000 {
		t.Fatalf("显式 token 预算应优先生效，实际 %d", got)
	}

	service = &Service{cfg: config.Config{AgentContextMaxChars: 24000}}
	if got := service.contextBudgetTokens(); got != 18000 {
		t.Fatalf("24000 字符应按 0.75 折算为 18000 token，实际 %d", got)
	}
}

func TestBuildModelMessagesAccountsForFixedContext(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for index := 0; index < 80; index++ {
		role := "user"
		if index%2 == 1 {
			role = "assistant"
		}
		if err := db.AddMessage(ctx, database.Message{
			ID:             fmt.Sprintf("budget-%02d", index),
			ConversationID: "conv-digest",
			Role:           role,
			Content:        strings.Repeat("这是一段用于验证固定 Prompt 预算的历史内容。", 120),
			CreatedAt:      now.Add(time.Duration(index) * time.Millisecond),
		}); err != nil {
			t.Fatalf("写入历史消息失败: %v", err)
		}
	}
	service := &Service{db: db, cfg: config.Config{AgentContextMaxTokens: 6000}}
	messages, err := service.buildModelMessages(ctx, "conv-digest", "user-1")
	if err != nil {
		t.Fatalf("构建模型消息失败: %v", err)
	}
	fixedTokens := estimateTextTokensV2(service.mainAgentInstruction(ctx)) +
		estimateToolsTokens(ctx, service.contextAgentTools(ctx)) + 8
	total := fixedTokens + estimateMessagesTokensV2(messages)
	if total > 6500 {
		t.Fatalf("固定上下文和历史未按总预算裁剪: %d", total)
	}
}
