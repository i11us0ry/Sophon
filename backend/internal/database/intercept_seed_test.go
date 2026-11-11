package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSeedDefaultInterceptRulesFromARTEX(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "intercept-seed.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rules, err := db.ListInterceptRules(context.Background())
	if err != nil {
		t.Fatalf("读取规则失败: %v", err)
	}
	if len(rules) != len(defaultInterceptRules) {
		t.Fatalf("内置规则数量应为 %d，实际 %d", len(defaultInterceptRules), len(rules))
	}
	byName := map[string]InterceptRule{}
	for _, rule := range rules {
		byName[rule.Name] = rule
	}
	for _, name := range []string{
		"[内置] 递归强制删除 rm -rf",
		"[内置] SQL DROP DATABASE / TABLE / SCHEMA",
		"[内置] 破坏性系统命令",
		"[内置] 删除类接口路径",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("缺少 ARTEX 内置规则: %s", name)
		}
	}
	if byName["[内置] 数据外泄管道"].Enabled {
		t.Fatal("数据外泄管道应保持 ARTEX 默认停用状态")
	}
	if err := db.seedDefaultInterceptRules(context.Background()); err != nil {
		t.Fatalf("重复种子失败: %v", err)
	}
	again, err := db.ListInterceptRules(context.Background())
	if err != nil || len(again) != len(rules) {
		t.Fatalf("种子应幂等: before=%d after=%d err=%v", len(rules), len(again), err)
	}
}
