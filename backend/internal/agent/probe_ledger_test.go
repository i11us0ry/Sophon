package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProbeSemanticKeyExtractsTargets(t *testing.T) {
	first := map[string]interface{}{
		"command": `H=falcon.example.com; curl -sk -X POST "https://$H/rc_oa_gateway/user/session.json"`,
	}
	second := map[string]interface{}{
		"command": `curl -sk --request POST https://falcon.example.com/rc_oa_gateway/user/session.json`,
	}
	firstKey := probeSemanticKey(first)
	secondKey := probeSemanticKey(second)
	if firstKey == "" || firstKey != secondKey {
		t.Fatalf("相同 Host/Path/Method 应生成相同语义键: %q %q", firstKey, secondKey)
	}
	target := extractProbeTarget(first)
	if len(target.hosts) != 1 || target.hosts[0] != "falcon.example.com" {
		t.Fatalf("Host 提取错误: %+v", target)
	}
	if len(target.paths) != 1 || target.paths[0] != "/rc_oa_gateway/user/session.json" {
		t.Fatalf("Path 提取错误: %+v", target)
	}
	if len(target.methods) != 1 || target.methods[0] != "POST" {
		t.Fatalf("Method 提取错误: %+v", target)
	}
}

func TestProbeLedgerGroupsAndAnnotatesRecentTargets(t *testing.T) {
	now := time.Now().UTC()
	args := map[string]interface{}{
		"command": "curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json",
	}
	entries := []database.ToolExecution{
		{ID: "tool-2", ToolName: "exec", Arguments: args, Status: "failed", StartedAt: now},
		{ID: "tool-1", ToolName: "exec", Arguments: args, Status: "completed", StartedAt: now.Add(-time.Minute)},
	}
	groups := buildProbeLedger(entries, 10)
	if len(groups) != 1 || groups[0].completed != 1 || groups[0].failed != 1 {
		t.Fatalf("探测账本聚合错误: %+v", groups)
	}
	text := formatProbeLedger(groups)
	if !strings.Contains(text, "completed×1/failed×1") ||
		!strings.Contains(text, "falcon.example.com") ||
		!strings.Contains(text, "/rc_oa_gateway/user/session.json") {
		t.Fatalf("探测账本文本错误:\n%s", text)
	}
	annotation := recentProbeAnnotation("猎鹰 https://falcon.example.com", map[string]bool{
		"falcon.example.com": true,
	})
	if !strings.Contains(annotation, "先写回测试结果") {
		t.Fatalf("最近探测资产未标注闭环提示: %q", annotation)
	}
}

func TestProjectNextTargetsMarksRecentlyProbedAsset(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_insert_assets", map[string]interface{}{
		"assets_json": `[{"name":"猎鹰","kind":"url","value":"https://falcon.example.com","criticality":"high"}]`,
	}); err != nil {
		t.Fatalf("写入资产失败: %v", err)
	}
	id := service.db.StartToolExecution(ctx, "conv-tools", "user-1", "exec", map[string]interface{}{
		"command": "curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json",
	})
	service.db.FinishToolExecution(ctx, id, "200", nil)

	output, err := invokeProjectTool(t, service, ctx, "project_next_targets", map[string]interface{}{
		"limit": 20,
	})
	if err != nil {
		t.Fatalf("读取未覆盖队列失败: %v", err)
	}
	if !strings.Contains(output, "最近已探测但尚未闭环") {
		t.Fatalf("未覆盖队列缺少闭环提示:\n%s", output)
	}
}
