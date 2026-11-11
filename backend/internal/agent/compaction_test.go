package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestGroupMessageRoundsKeepsPairsTogether(t *testing.T) {
	messages := []database.Message{
		{ID: "u1", Role: "user"},
		{ID: "a1", Role: "assistant"},
		{ID: "u2", Role: "user"},
		{ID: "a2", Role: "assistant"},
		{ID: "a3", Role: "assistant"},
	}
	rounds := groupMessageRounds(messages)
	if len(rounds) != 2 {
		t.Fatalf("应切分为 2 个回合，实际 %d", len(rounds))
	}
	if len(rounds[0]) != 2 || len(rounds[1]) != 3 {
		t.Fatalf("回合内消息分配错误: %+v", rounds)
	}
}

func TestSoftBudgetMessagesKeepsNewestRounds(t *testing.T) {
	content := strings.Repeat("数据", 400)
	messages := []database.Message{
		{ID: "u1", Role: "user", Content: content},
		{ID: "a1", Role: "assistant", Content: content},
		{ID: "u2", Role: "user", Content: content},
		{ID: "a2", Role: "assistant", Content: content},
		{ID: "u3", Role: "user", Content: content},
		{ID: "a3", Role: "assistant", Content: content},
	}
	out := softBudgetMessages(messages, 1000)
	if len(out) != 2 {
		t.Fatalf("预算内应只保留最新一个回合，实际 %d 条", len(out))
	}
	if out[0].ID != "u3" || out[1].ID != "a3" {
		t.Fatalf("应保留最新回合 u3/a3，实际 %s/%s", out[0].ID, out[1].ID)
	}

	single := softBudgetMessages([]database.Message{
		{ID: "u1", Role: "user", Content: strings.Repeat("很长的内容", 500)},
	}, 200)
	if len(single) != 1 || !strings.Contains(single[0].Content, contextTruncateMarker) {
		t.Fatalf("单回合超预算时应截断并保留标记: %+v", single)
	}
}

func TestCompactConversationWritesSummaryTranscriptAndUsage(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	root := t.TempDir()
	now := time.Now().UTC()
	content := strings.Repeat("测试数据", 150)

	for index := 0; index < 6; index += 1 {
		role := "user"
		if index%2 == 1 {
			role = "assistant"
		}
		if err := db.AddMessage(ctx, database.Message{
			ID:             fmt.Sprintf("msg-%d", index),
			ConversationID: "conv-digest",
			Role:           role,
			Content:        content,
			CreatedAt:      now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("写入消息失败: %v", err)
		}
	}

	service := &Service{
		db: db,
		cfg: config.Config{
			AgentContextMaxChars: 4000,
			Storage:              config.StorageConfig{ArtifactRoot: root},
		},
		model: &stubSummaryModel{content: "## 1. 授权范围与约束\n无\n## 7. 当前进度、失败与下一步\n继续扫描"},
	}
	if err := service.compactConversation(ctx, "conv-digest", "user-1", compactionKindMajor); err != nil {
		t.Fatalf("压缩失败: %v", err)
	}

	stored, err := db.GetConversationSummary(ctx, "conv-digest")
	if err != nil {
		t.Fatalf("读取摘要失败: %v", err)
	}
	if stored == nil || stored.Version != 1 {
		t.Fatalf("摘要版本应为 1: %+v", stored)
	}
	if stored.TokenBefore <= 0 || stored.TokenAfter <= 0 {
		t.Fatalf("应记录压缩前后 token: %+v", stored)
	}
	if stored.TranscriptPath == "" {
		t.Fatal("应写入 transcript 路径")
	}
	if _, err := os.Stat(stored.TranscriptPath); err != nil {
		t.Fatalf("transcript 文件不存在: %v", err)
	}

	compactions, err := db.ListContextCompactions(ctx, "conv-digest", 10)
	if err != nil {
		t.Fatalf("读取压缩记录失败: %v", err)
	}
	if len(compactions) != 1 {
		t.Fatalf("应有 1 条压缩审计，实际 %d", len(compactions))
	}
	if compactions[0].Kind != compactionKindMajor {
		t.Fatalf("压缩审计应记录 kind=major，实际 %s", compactions[0].Kind)
	}

	var summaryUsage int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage WHERE kind = 'summary'`,
	).Scan(&summaryUsage); err != nil {
		t.Fatalf("查询摘要用量失败: %v", err)
	}
	if summaryUsage != 1 {
		t.Fatalf("摘要调用应计入 token_usage(kind=summary)，实际 %d", summaryUsage)
	}
}
