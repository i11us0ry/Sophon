package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/execctx"
)

func TestSemanticWriteKeyDeduplicatesSameHypothesis(t *testing.T) {
	first := `{"hypothesis_id":"h-1","result":"tested_clean","evidence":"probe1","evidence_refs":["artifact:/tmp/a"]}`
	second := `{"hypothesis_id":"h-1","result":"tested_clean","evidence":"probe2","evidence_refs":["artifact:/tmp/b"]}`
	if semanticWriteKey("project_complete_hypothesis", first) != semanticWriteKey("project_complete_hypothesis", second) {
		t.Fatal("同一假设的重试应共享语义去重键")
	}
	third := `{"hypothesis_id":"h-2","result":"tested_clean"}`
	if semanticWriteKey("project_complete_hypothesis", first) == semanticWriteKey("project_complete_hypothesis", third) {
		t.Fatal("不同假设不应共享去重键")
	}
}

func TestSemanticWriteKeyKeepsDifferentOutcomes(t *testing.T) {
	clean := `{"hypothesis_id":"h-1","status":"tested_clean","result":"clean","evidence":"probe1"}`
	confirmed := `{"hypothesis_id":"h-1","status":"confirmed","result":"vuln","finding_id":"f-1","evidence":"probe2"}`
	if semanticWriteKey("project_complete_hypothesis", clean) ==
		semanticWriteKey("project_complete_hypothesis", confirmed) {
		t.Fatal("同一假设的不同结论必须可以再次写回")
	}
	testClean := `{"asset_id":"a-1","dimension":"XSS","status":"tested_clean","result":"clean"}`
	testConfirmed := `{"asset_id":"a-1","dimension":"XSS","status":"confirmed","result":"vuln","finding_id":"f-1"}`
	if semanticWriteKey("project_record_test", testClean) ==
		semanticWriteKey("project_record_test", testConfirmed) {
		t.Fatal("同一测试维度的不同结果必须可以再次写回")
	}
}

func TestTurnToolCacheKindScopesReadsByArguments(t *testing.T) {
	a := turnToolCacheKind("project_list", `{"resource":"facts","limit":10,"asset_id":"a"}`)
	b := turnToolCacheKind("project_list", `{"asset_id":"a","limit":10,"resource":"facts"}`)
	c := turnToolCacheKind("project_list", `{"resource":"facts","limit":20,"asset_id":"a"}`)
	if a == "" || a != b {
		t.Fatalf("参数顺序不同但内容相同的读调用应共享缓存键: %q %q", a, b)
	}
	if a == c {
		t.Fatal("参数不同的读调用不应共享缓存键")
	}
	getA := turnToolCacheKind("project_get", `{"resource":"finding","finding_id":"f-1"}`)
	getB := turnToolCacheKind("project_get", `{"finding_id":"f-1","resource":"finding"}`)
	getC := turnToolCacheKind("project_get", `{"resource":"finding","finding_id":"f-2"}`)
	if getA == "" || getA != getB {
		t.Fatalf("project_get 相同参数的读调用应共享缓存键: %q %q", getA, getB)
	}
	if getA == getC {
		t.Fatal("project_get 不同对象的读调用不应共享缓存键")
	}
	if turnToolCacheKind("exec", `{"command":"ls"}`) != "" {
		t.Fatal("exec 不应进入同轮业务去重缓存")
	}
}

func TestTurnToolCacheKindScopesSkillsByArguments(t *testing.T) {
	first := turnToolCacheKind(readSkillToolName, `{"name":"dotnet-code-audit"}`)
	same := turnToolCacheKind(readSkillToolName, `{ "name": "dotnet-code-audit" }`)
	other := turnToolCacheKind(readSkillToolName, `{"name":"dotnet-injection-audit"}`)
	if first == "" || first != same {
		t.Fatalf("同名技能应共享缓存键: %q %q", first, same)
	}
	if first == other {
		t.Fatal("不同技能不应共享缓存键")
	}
}

func TestReadSkillUsesTurnCache(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = execctx.WithMessageID(ctx, "msg-skill-cache")
	raw := `{"name":"dotnet-code-audit"}`
	kind := turnToolCacheKind(readSkillToolName, raw)
	service.storeTurnToolCache(ctx, readSkillToolName, kind, "cached skill body")

	got, ok := service.lookupTurnToolCache(ctx, readSkillToolName, kind)
	if !ok || got != "cached skill body" {
		t.Fatalf("read_skill 未命中本轮缓存: got=%q ok=%v", got, ok)
	}
}

func TestReadSkillCacheIsIsolatedPerSubagent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = execctx.WithMessageID(ctx, "msg-skill-scope")
	raw := `{"name":"dotnet-code-audit"}`
	kind := turnToolCacheKind(readSkillToolName, raw)
	workerA := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-a", Kind: "worker", Mode: subagentModeReadOnly, Depth: 1,
		AllowedSkills: []string{"dotnet-code-audit"},
	})
	workerB := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-b", Kind: "worker", Mode: subagentModeReadOnly, Depth: 1,
		AllowedSkills: []string{"dotnet-injection-audit"},
	})
	service.storeTurnToolCache(workerA, readSkillToolName, kind, "worker A skill body")

	if _, ok := service.lookupTurnToolCache(workerB, readSkillToolName, kind); ok {
		t.Fatal("Worker B 不应命中 Worker A 的技能缓存")
	}
	got, ok := service.lookupTurnToolCache(workerA, readSkillToolName, kind)
	if !ok || got != "worker A skill body" {
		t.Fatalf("Worker A 应命中自己的技能缓存: got=%q ok=%v", got, ok)
	}
}

func TestLookupRecentProbeExecutionAcrossTurns(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	args := map[string]interface{}{
		"command": "curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json",
	}
	id := service.db.StartToolExecution(ctx, "conv-tools", "user-1", "exec", args)
	service.db.FinishToolExecution(ctx, id, `{"code":0}`, nil)

	previous, ok := service.lookupRecentProbeExecution(
		ctx,
		"exec",
		`{"command":"curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json"}`,
	)
	if !ok || previous == nil || previous.ID != id {
		t.Fatalf("跨轮探测未命中: previous=%+v ok=%v", previous, ok)
	}
	if _, ok := service.lookupRecentProbeExecution(
		ctx,
		"exec",
		`{"command":"curl -sk https://falcon.example.com/rc_oa_gateway/query_all_user"}`,
	); ok {
		t.Fatal("不同参数不应命中探测缓存")
	}
	if !isProbeReplayTool("execute-python-script") || isProbeReplayTool("project_list") {
		t.Fatal("探测工具分类错误")
	}
}

func TestProbeResultIncludesEvidenceReference(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	args := map[string]interface{}{
		"command": "curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json",
	}
	startedAt := time.Now().UTC()
	id := service.db.StartToolExecution(ctx, "conv-tools", "user-1", "exec", args)
	service.db.FinishToolExecution(ctx, id, "200", nil)
	observed := &observedTool{service: service, name: "exec"}
	result := observed.withEvidenceFooter(
		ctx,
		`{"command":"curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json"}`,
		"200",
		startedAt,
	)
	if !strings.Contains(result, "tool:"+id) {
		t.Fatalf("探测结果缺少证据引用: %s", result)
	}
}
