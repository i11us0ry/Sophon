package storage

import "testing"

func TestCleanupCategoriesIncludeAuditTables(t *testing.T) {
	for _, name := range []string{"process_details", "reasoning_content", "context_compactions", "memory_writes"} {
		if _, ok := CategoryByName(name); !ok {
			t.Fatalf("清理类别缺少 %s", name)
		}
	}
}
