package storage

import (
	"testing"
)

func TestIntelSearchesRetentionCategory(t *testing.T) {
	category, ok := CategoryByName("intel_searches")
	if !ok || category.Table != "intel_searches" || category.TimeColumn != "created_at" {
		t.Fatalf("信息收集历史清理类别缺失或配置错误: %+v", category)
	}
}
