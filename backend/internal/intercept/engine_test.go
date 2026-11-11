package intercept

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func openInterceptTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "intercept.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestEvaluateUsesPriorityAndFirstMatch(t *testing.T) {
	db := openInterceptTestDB(t)
	now := time.Now().UTC()
	for _, rule := range []database.InterceptRule{
		{
			ID: "allow-exec", Name: "allow exec", Enabled: true, Priority: 10,
			MatchTarget: TargetToolName, MatchType: MatchString, Pattern: "exec",
			Action: ActionAllow, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "deny-exec", Name: "deny exec", Enabled: true, Priority: 100,
			MatchTarget: TargetToolName, MatchType: MatchString, Pattern: "exec",
			Action: ActionDeny, Message: "禁止 exec", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateInterceptRule(context.Background(), rule); err != nil {
			t.Fatalf("写入规则失败: %v", err)
		}
	}
	decision, err := Evaluate(context.Background(), db, "exec", map[string]interface{}{"command": "ls"})
	if err != nil {
		t.Fatalf("评估规则失败: %v", err)
	}
	if decision == nil || decision.Action != ActionDeny || decision.Reason != "禁止 exec" {
		t.Fatalf("优先级最高的规则应先命中: %+v", decision)
	}
}

func TestEvaluateMatchesToolInputRegex(t *testing.T) {
	db := openInterceptTestDB(t)
	now := time.Now().UTC()
	rule := database.InterceptRule{
		ID: "deny-rm", Name: "deny rm", Enabled: true, Priority: 50,
		MatchTarget: TargetToolInput, MatchType: MatchRegex,
		Pattern: `rm\s+-rf`, Action: ActionDeny, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateInterceptRule(context.Background(), rule); err != nil {
		t.Fatalf("写入规则失败: %v", err)
	}
	decision, err := Evaluate(context.Background(), db, "exec", map[string]interface{}{"command": "rm -rf /tmp/demo"})
	if err != nil || decision == nil || decision.Action != ActionDeny {
		t.Fatalf("tool_input 正则应命中: decision=%+v err=%v", decision, err)
	}
}

func TestValidateRuleRejectsInvalidRegex(t *testing.T) {
	rule := database.InterceptRule{
		Name: "bad regex", MatchTarget: TargetToolInput, MatchType: MatchRegex,
		Pattern: "([", Action: ActionDeny, Priority: 10,
	}
	if err := ValidateRule(&rule); err == nil {
		t.Fatal("非法正则应被拒绝")
	}
}
