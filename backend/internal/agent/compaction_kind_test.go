package agent

import (
	"context"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestNextCompactionKind(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	service := &Service{db: db, cfg: config.Config{AgentContextMaxChars: 4000}}

	if kind := service.nextCompactionKind(ctx, "conv-digest"); kind != compactionKindMajor {
		t.Fatalf("无摘要时应做 major，实际 %s", kind)
	}

	save := func(version, tokenAfter int) {
		t.Helper()
		if err := db.SaveConversationSummary(ctx, database.ConversationSummary{
			ConversationID:   "conv-digest",
			Summary:          "摘要",
			ThroughMessageID: "msg-1",
			Version:          version,
			TokenBefore:      1000,
			TokenAfter:       tokenAfter,
			UpdatedAt:        time.Now().UTC(),
		}); err != nil {
			t.Fatalf("保存摘要失败: %v", err)
		}
	}

	save(2, 100)
	if kind := service.nextCompactionKind(ctx, "conv-digest"); kind != compactionKindMinor {
		t.Fatalf("普通版本应为 minor，实际 %s", kind)
	}

	save(5, 100)
	if kind := service.nextCompactionKind(ctx, "conv-digest"); kind != compactionKindMajor {
		t.Fatalf("每 %d 次应做 major，实际 %s", compactionMajorEveryN, kind)
	}

	// 摘要本身超过预算 25% 时也做 major。
	oversized := service.contextBudgetTokens()/4 + 100
	save(2, oversized)
	if kind := service.nextCompactionKind(ctx, "conv-digest"); kind != compactionKindMajor {
		t.Fatalf("摘要超预算应做 major，实际 %s", kind)
	}
}

func TestReserveCompactionGuardsInFlightAndCooldown(t *testing.T) {
	db := openDigestTestDB(t)
	service := &Service{db: db, cfg: config.Config{AgentContextMaxChars: 4000}}

	if _, ok := service.reserveCompaction("conv-digest"); !ok {
		t.Fatalf("首次压缩应放行")
	}
	if _, ok := service.reserveCompaction("conv-digest"); ok {
		t.Fatalf("压缩在途时不应重复放行")
	}
	service.releaseCompaction("conv-digest")
	if _, ok := service.reserveCompaction("conv-digest"); ok {
		t.Fatalf("冷却期内不应再次放行")
	}
}
