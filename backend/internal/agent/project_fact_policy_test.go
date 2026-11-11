package agent

import "testing"

func TestNormalizeProjectFactKey(t *testing.T) {
	cases := []struct {
		raw        string
		factType   string
		memoryKind string
		want       string
	}{
		{"target/primary_domain", "general", "", "target/primary-domain"},
		{"docs.qq.com-开放重定向外域参数被WAF501拦截(20261023)", "recon", "", "target/docs.qq.com-开放重定向外域参数被waf501拦截"},
		{"admin:123456", "credential", "credential", "auth/admin:123456"},
		{"service-status-a", "general", "", "service-status-a"},
	}
	for _, item := range cases {
		got, err := normalizeProjectFactKey(item.raw, item.factType, item.memoryKind)
		if err != nil {
			t.Fatalf("normalizeProjectFactKey(%q) 失败: %v", item.raw, err)
		}
		if got != item.want {
			t.Fatalf("normalizeProjectFactKey(%q) = %q, want %q", item.raw, got, item.want)
		}
	}
	if _, err := normalizeProjectFactKey("unknown/category", "general", ""); err == nil {
		t.Fatalf("非法分类应返回错误")
	}
	if _, err := normalizeProjectFactKey("finding/sqli", "general", ""); err == nil {
		t.Fatalf("finding/ 事实分类应被拒绝")
	}
}

func TestRecordFactRejectsTestResultAndFinding(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "target/test", "summary": "测试结果", "fact_type": "test_result",
	}); err == nil {
		t.Fatalf("test_result 事实应被拒绝")
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "finding/sqli", "summary": "漏洞结果", "fact_type": "finding",
	}); err == nil {
		t.Fatalf("finding 事实应被拒绝")
	}
}
