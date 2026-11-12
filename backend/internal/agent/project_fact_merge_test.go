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

func TestRecordFactMergesDifferentTypesWithSameStructuredIdentity(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	first := map[string]interface{}{
		"key":          "infra/service-a-version",
		"summary":      "服务 A 的版本为 1.0",
		"fact_type":    "topology",
		"subject_type": "service",
		"subject_key":  "service-a",
		"predicate":    "version",
		"object_type":  "version",
		"object_key":   "1.0",
		"confidence":   90,
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", first); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	second := map[string]interface{}{
		"key":          "infra/service-a-version-recheck",
		"summary":      "服务 A 的版本为 1.0，复核一致",
		"fact_type":    "infra",
		"subject_type": "service",
		"subject_key":  "service-a",
		"predicate":    "version",
		"object_type":  "version",
		"object_key":   "1.0",
		"confidence":   95,
		"evidence":     "服务响应头 Server: A/1.0",
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", second); err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 || facts[0].Version < 2 {
		t.Fatalf("相同结构化主体/谓词应合并，实际 %+v", facts)
	}
}

func TestRecordFactDoesNotMergeAcrossDifferentFamilies(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	for _, item := range []map[string]interface{}{
		{
			"key": "infra/service-b-version", "summary": "服务 B 版本 2.0",
			"fact_type": "infra", "subject_type": "service", "subject_key": "service-b",
			"predicate": "version", "object_key": "2.0", "confidence": 90,
		},
		{
			"key": "exploit/service-b-version", "summary": "服务 B 版本 2.0 可利用路径",
			"fact_type": "exploit", "subject_type": "service", "subject_key": "service-b",
			"predicate": "version", "object_key": "2.0", "confidence": 95,
		},
	} {
		if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", item); err != nil {
			t.Fatalf("写入事实失败: %v", err)
		}
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 2 {
		t.Fatalf("跨 key family 的事实不应自动合并，实际 %+v", facts)
	}
}
