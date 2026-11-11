package agent

import "testing"

func TestRecordFactMergesDateVariants(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":        "docs.qq.com-开放重定向被WAF拦截(20261023)",
		"summary":    "外域参数返回 WAF 501",
		"confidence": 80,
	}); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":        "docs.qq.com-开放重定向被WAF拦截(20261024)",
		"summary":    "外域参数返回 WAF 501，补充复测证据",
		"confidence": 95,
		"evidence":   "curl 返回 WAF 501",
	}); err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("日期变体应合并为一条事实，实际 %d 条", len(facts))
	}
	if facts[0].Version < 2 {
		t.Fatalf("合并后版本应递增: %+v", facts[0])
	}
}
