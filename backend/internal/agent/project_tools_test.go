package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/tool"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

func openProjectToolService(t *testing.T, withProject bool) (*Service, context.Context) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "project-tools.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	projectID := ""
	if withProject {
		projectID = "project-tools"
		if err := db.CreateProject(ctx, database.Project{
			ID:          projectID,
			OwnerUserID: "user-1",
			Name:        "工具测试项目",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
		if err := db.CreateProjectGraphNode(ctx, database.GraphNode{
			ID:         "begin-project-tools",
			ProjectID:  projectID,
			Kind:       "begin",
			Title:      "外部攻击者",
			Status:     "open",
			Confidence: 90,
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("创建测试起点失败: %v", err)
		}
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-tools",
		OwnerUserID: "user-1",
		ProjectID:   projectID,
		Title:       "工具测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}

	service := &Service{db: db, cfg: config.Config{}}
	service.vulnerabilityReviewHook = func(context.Context, database.Vulnerability) error {
		return nil
	}
	t.Cleanup(func() {
		if !service.WaitForBackgroundTasks(5 * time.Second) {
			t.Errorf("后台任务未在测试清理前完成")
		}
	})
	toolCtx := execctx.WithUserID(ctx, "user-1")
	toolCtx = execctx.WithConversationID(toolCtx, "conv-tools")
	return service, toolCtx
}

func invokeProjectTool(
	t *testing.T,
	service *Service,
	ctx context.Context,
	name string,
	args map[string]interface{},
) (string, error) {
	t.Helper()
	if resource, ok := legacyProjectListResource(name); ok {
		converted := make(map[string]interface{}, len(args)+1)
		for key, value := range args {
			converted[key] = value
		}
		converted["resource"] = resource
		name = "project_list"
		args = converted
	}
	if resource, ok := legacyProjectGetResource(name); ok {
		converted := make(map[string]interface{}, len(args)+1)
		for key, value := range args {
			converted[key] = value
		}
		converted["resource"] = resource
		idKey := map[string]string{
			"asset":      "asset_id",
			"finding":    "finding_id",
			"graph_node": "node_id",
		}[resource]
		if id, ok := converted[idKey].(string); ok && strings.TrimSpace(id) != "" {
			converted["id"] = id
		}
		name = "project_get"
		args = converted
	}
	var target tool.BaseTool
	for _, item := range newProjectTools(service) {
		info, err := item.Info(context.Background())
		if err != nil {
			t.Fatalf("读取工具信息失败: %v", err)
		}
		if info != nil && info.Name == name {
			target = item
			break
		}
	}
	if target == nil {
		t.Fatalf("未找到工具 %s", name)
	}
	invokable, ok := target.(tool.InvokableTool)
	if !ok {
		t.Fatalf("工具 %s 未实现 InvokableTool", name)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	return invokable.InvokableRun(ctx, string(raw))
}

func TestNewServiceRegistersProjectTools(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "register.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()

	service, err := NewService(db, config.Config{AgentMock: true}, nil, nil)
	if err != nil {
		t.Fatalf("创建 Service 失败: %v", err)
	}
	required := []string{
		"project_list",
		"project_get",
		"project_record_audit",
		"project_record_fact",
		"project_insert_assets",
		"project_report_finding",
		"project_record_test",
		"project_plan_hypotheses",
		"project_start_hypothesis",
		"project_complete_hypothesis",
		"project_upsert_entity",
		"project_link_entities",
		"project_memory_graph",
		"project_fact_audit",
		"project_graph_overview",
		"project_sync_graph",
		"project_add_intent",
		"project_add_hint",
		"project_update_goal",
		"project_update_intent",
		"project_update_finding",
	}
	available := map[string]bool{}
	for _, item := range service.baseTools {
		info, err := item.Info(context.Background())
		if err == nil && info != nil {
			available[info.Name] = true
		}
	}
	for _, name := range required {
		if !available[name] {
			t.Fatalf("内置工具 %s 未注册到 Agent: %v", name, available)
		}
	}
}

func TestProjectListAggregatesReadOnlyListTools(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.tools = newProjectTools(service)
	inventory := service.ToolInventory(ctx)
	direct := map[string]InventoryTool{}
	for _, item := range inventory.Direct {
		direct[item.Name] = item
	}
	toolItem, ok := direct["project_list"]
	if !ok {
		t.Fatalf("project_list 应直接暴露给模型")
	}
	for _, legacy := range []string{
		"project_list_facts",
		"project_list_assets",
		"project_list_findings",
		"project_list_hypotheses",
		"project_list_entities",
		"project_list_chains",
	} {
		if _, exposed := direct[legacy]; exposed {
			t.Fatalf("旧列表工具 %s 不应继续直接暴露", legacy)
		}
	}
	var resourceParam *ToolParameter
	for index := range toolItem.Parameters {
		if toolItem.Parameters[index].Name == "resource" {
			resourceParam = &toolItem.Parameters[index]
			break
		}
	}
	if resourceParam == nil || !resourceParam.Required || len(resourceParam.Enum) != 6 {
		t.Fatalf("project_list.resource schema 异常: %+v", resourceParam)
	}

	output, err := invokeProjectTool(t, service, ctx, "project_list", map[string]interface{}{
		"resource": "assets",
		"limit":    2,
		"view":     "summary",
	})
	if err != nil || !strings.Contains(output, "没有匹配的资产") {
		t.Fatalf("project_list assets 查询失败: %q %v", output, err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_list", map[string]interface{}{
		"resource": "assets",
		"severity": "high",
	}); err == nil || !strings.Contains(err.Error(), "不支持参数 severity") {
		t.Fatalf("不适用的过滤参数应被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_list", map[string]interface{}{
		"resource": "unknown",
	}); err == nil {
		t.Fatal("未知 resource 应返回错误")
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_list", map[string]interface{}{
		"resource": "assets",
		"foo":      "bar",
	}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("未知字段应被拒绝: %v", err)
	}
	if projectListLimit("entities", 999, "detail") != 200 {
		t.Fatal("entities 应恢复原有 200 条上限")
	}
	if projectListLimit("hypotheses", 999, "detail") != 100 {
		t.Fatal("hypotheses 应恢复原有 100 条上限")
	}
	for _, resource := range []string{"facts", "assets", "findings", "hypotheses", "entities"} {
		if _, err := invokeProjectTool(t, service, ctx, "project_list", map[string]interface{}{
			"resource": resource,
			"name":     "not-found",
			"size":     5,
		}); err != nil {
			t.Fatalf("resource=%s 应支持 name/size 兼容参数: %v", resource, err)
		}
	}
}

func TestRunCaptureTracksProjectListResource(t *testing.T) {
	capture := &runCapture{}
	capture.recordToolCall("list-assets", "project_list")
	capture.recordToolArguments("project_list", `{"resource":"assets","limit":10}`)
	if !capture.hasProjectListResource("assets") {
		t.Fatal("project_list resource 应写入运行捕获")
	}
	if capture.hasProjectListResource("facts") {
		t.Fatal("未查询的 resource 不应被标记")
	}
	merged := &runCapture{}
	merged.mergeEvidence(capture)
	if !merged.hasProjectListResource("assets") {
		t.Fatal("合并运行证据后应保留 project_list resource")
	}
}

func TestCurrentCampaignRejectsCrossProjectRequest(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProject(ctx, database.Project{
		ID:          "project-other",
		OwnerUserID: "user-1",
		Name:        "其他项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-other",
		ProjectID:   "project-other",
		OwnerUserID: "user-1",
		Name:        "other.example.com",
		Kind:        "domain",
		Value:       "other.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建其他项目资产失败: %v", err)
	}
	if err := service.db.CreateProjectSessionCampaign(
		ctx,
		database.ConversationBatch{
			ID:          "campaign-other",
			OwnerUserID: "user-1",
			ProjectID:   "project-other",
			Title:       "其他项目任务",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		database.Conversation{
			ID:          "conversation-other",
			OwnerUserID: "user-1",
			ProjectID:   "project-other",
			Title:       "其他项目任务",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		"执行测试",
	); err != nil {
		t.Fatalf("创建其他项目任务失败: %v", err)
	}
	if _, _, _, err := service.currentCampaign(ctx, "campaign-other"); err == nil ||
		!strings.Contains(err.Error(), "不属于当前项目") {
		t.Fatalf("跨项目 campaign 必须被拒绝: %v", err)
	}
}

func TestProjectToolsRequireProjectBinding(t *testing.T) {
	service, ctx := openProjectToolService(t, false)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "10.0.0.1",
	}); err == nil || !strings.Contains(err.Error(), "未绑定项目") {
		t.Fatalf("未绑定项目时应报错，实际: %v", err)
	}
}

func TestProjectToolsRejectInactiveProject(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Status = "paused"
	project.UpdatedAt = time.Now().UTC()
	if err := service.db.UpdateProject(ctx, *project); err != nil {
		t.Fatalf("暂停项目失败: %v", err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "summary": "10.0.0.1",
	}); err == nil || !strings.Contains(err.Error(), "不允许执行 Agent 工作") {
		t.Fatalf("非进行中项目应拒绝项目工具: %v", err)
	}
}

func TestProjectFactToolRoundTrip(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-1",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "目标主机",
		Kind:        "ip",
		Value:       "10.0.0.1",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建测试资产失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":        "目标IP",
		"summary":    "目标 IP 为 10.0.0.1",
		"body":       "nmap 确认主机开放 80/443",
		"evidence":   "nmap -sV 10.0.0.1 输出",
		"relation":   "asset:asset-1",
		"confidence": 95,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	if !strings.Contains(out, "项目事实") || !strings.Contains(out, "判定") {
		t.Fatalf("写入结果异常: %q", out)
	}

	out, err = invokeProjectTool(t, service, ctx, "project_list_facts", map[string]interface{}{})
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if !strings.Contains(out, "目标 IP 为 10.0.0.1") ||
		!strings.Contains(out, "relation=asset:asset-1") ||
		!strings.Contains(out, "95") {
		t.Fatalf("事实列表缺少内容: %q", out)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 {
		t.Fatalf("读取结构化事实失败: %+v, err=%v", facts, err)
	}
	if facts[0].Summary != "目标 IP 为 10.0.0.1" ||
		facts[0].Body != "nmap 确认主机开放 80/443" ||
		facts[0].Evidence != "nmap -sV 10.0.0.1 输出" ||
		facts[0].Relation != "asset:asset-1" {
		t.Fatalf("结构化事实字段不完整: %+v", facts[0])
	}

	// 低置信、无证据的覆盖请求应被拒绝（审计修复）：事实保持原值。
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "目标 IP 已更新", "asset_id": "asset-1",
	}); err != nil {
		t.Fatalf("低置信覆盖不应报错: %v", err)
	}
	facts, err = service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 || facts[0].Summary != "目标 IP 为 10.0.0.1" {
		t.Fatalf("低置信无证据覆盖应被拒绝: %+v, err=%v", facts, err)
	}

	// 提供更高置信度后允许同 key 幂等更新，且空 body 保留原值。
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "目标 IP 已更新", "confidence": 99, "asset_id": "asset-1",
	}); err != nil {
		t.Fatalf("高置信更新失败: %v", err)
	}
	facts, err = service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 ||
		facts[0].Value != "目标 IP 已更新" ||
		facts[0].Summary != "目标 IP 已更新" ||
		facts[0].Body != "nmap 确认主机开放 80/443" {
		t.Fatalf("高置信同 key 应幂等更新: %+v, err=%v", facts, err)
	}
}

func TestProjectRecordFactSkipsMissingIntent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-missing-intent",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "缺失意图测试资产",
		Kind:        "ip",
		Value:       "10.0.0.2",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建测试资产失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"asset_id":  "asset-missing-intent",
		"intent_id": "missing-intent",
		"key":       "缺失意图事实",
		"summary":   "事实应正常写入",
	})
	if err != nil {
		t.Fatalf("无效 intent_id 不应阻断事实写入: %v", err)
	}
	if !strings.Contains(out, "事实已写入但未关联 intent") {
		t.Fatalf("写入结果缺少无效意图提示: %q", out)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 {
		t.Fatalf("事实未正常写入: %+v err=%v", facts, err)
	}
	if strings.Contains(facts[0].Relation, "intent:missing-intent") {
		t.Fatalf("无效 intent_id 不应写入事实关系: %+v", facts[0])
	}
	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取图谱边失败: %v", err)
	}
	for _, edge := range edges {
		if edge.SrcID == "missing-intent" && edge.Rel == "yields" {
			t.Fatalf("无效 intent_id 不应建立图谱边: %+v", edge)
		}
	}
}

func TestProjectAssetToolDedup(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	args := map[string]interface{}{
		"assets_json": `[
			{"name":"主站","kind":"url","value":"https://a.com"},
			{"name":"重复","kind":"url","value":"https://a.com"},
			{"kind":"domain","value":"a.com"}
		]`,
	}
	out, err := invokeProjectTool(t, service, ctx, "project_insert_assets", args)
	if err != nil {
		t.Fatalf("写入资产失败: %v", err)
	}
	if !strings.Contains(out, "共写入 2 个资产，跳过 1 个") {
		t.Fatalf("首次写入结果异常: %q", out)
	}
	out, err = invokeProjectTool(t, service, ctx, "project_insert_assets", args)
	if err != nil {
		t.Fatalf("重复写入失败: %v", err)
	}
	if !strings.Contains(out, "共写入 0 个资产，跳过 3 个") {
		t.Fatalf("重复资产应全部跳过: %q", out)
	}
	out, err = invokeProjectTool(t, service, ctx, "project_list_assets", map[string]interface{}{})
	if err != nil || !strings.Contains(out, "https://a.com") {
		t.Fatalf("资产列表异常: %q, err=%v", out, err)
	}
}

func TestProjectAssetToolRejectsUnsupportedKinds(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	_, err := invokeProjectTool(t, service, ctx, "project_insert_assets", map[string]interface{}{
		"assets_json": `[
			{"name":"合法项","kind":"url","value":"https://a.com"},
			{"name":"非法项","kind":"endpoint","value":"https://b.com"}
		]`,
	})
	if err == nil || !strings.Contains(err.Error(), "只能是 domain/ip/url/port/host") {
		t.Fatalf("非标准资产类型应被拒绝: %v", err)
	}
	assets, err := service.db.ListProjectAssets(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目资产失败: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("批次含非法类型时不应部分写入: %+v", assets)
	}
}

func TestProjectAssetToolAcceptsExpandedKinds(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	out, err := invokeProjectTool(t, service, ctx, "project_insert_assets", map[string]interface{}{
		"assets_json": `[
			{"name":"端口","kind":"port","value":"443"},
			{"name":"主机","kind":"host","value":"app.internal"}
		]`,
	})
	if err != nil {
		t.Fatalf("写入 port/host 资产失败: %v", err)
	}
	if !strings.Contains(out, "共写入 2 个资产") {
		t.Fatalf("port/host 写入结果异常: %q", out)
	}
	assets, err := service.db.ListProjectAssets(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目资产失败: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("应写入 2 个资产: %+v", assets)
	}
}

func TestInferFindingAssetKindReturnsSupportedKinds(t *testing.T) {
	testCases := map[string]string{
		"https://a.com/x": "url",
		"10.0.0.1":        "ip",
		"a.com":           "domain",
		"443":             "port",
		"10.0.0.0/24":     "host",
		"internal-host":   "host",
		"opaque target":   "",
		"internal target": "",
		"src/WebSite/bin/Kingdee.BOS.FileServer.Web.dll : Kingdee.BOS.FileServer.Web.FileService.Upload2Attachment rva=0x2D24": "",
	}
	for value, expected := range testCases {
		kind := inferFindingAssetKind(value)
		if kind != expected || (kind != "" && !database.IsSupportedAssetKind(kind)) {
			t.Fatalf("目标 %q 类型错误: got=%q want=%q", value, kind, expected)
		}
	}
}

func TestProjectFindingAndGraphTools(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	evidenceRefs := []string{
		completedToolRef(t, service, ctx, "sqlmap"),
		completedToolRef(t, service, ctx, "http-probe"),
	}
	out, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":         "SQL 注入",
		"severity":      "high",
		"description":   "id 参数可注入",
		"target":        "https://a.com/x?id=1",
		"poc":           "GET /x?id=1%20AND%201=1",
		"impact":        "可读取数据库数据",
		"evidence_refs": evidenceRefs,
	}))
	if err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	if !strings.Contains(out, "已上报漏洞") {
		t.Fatalf("上报结果异常: %q", out)
	}

	out, err = invokeProjectTool(t, service, ctx, "project_list_findings", map[string]interface{}{})
	if err != nil ||
		!strings.Contains(out, "SQL 注入") ||
		!strings.Contains(out, "[high/open/verified]") ||
		!strings.Contains(out, "evidenceRefs=2") {
		t.Fatalf("漏洞列表异常: %q, err=%v", out, err)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("读取结构化漏洞失败: %+v, err=%v", findings, err)
	}
	if !strings.HasPrefix(findings[0].ReproductionSteps, "GET /x?id=1%20AND%201=1") ||
		!strings.Contains(findings[0].ReproductionSteps, "利用脚本（优先 Python）") ||
		findings[0].Impact != "可读取数据库数据" ||
		len(findings[0].EvidenceRefs) != 2 ||
		findings[0].AssetID == "" {
		t.Fatalf("结构化漏洞字段不完整: %+v", findings[0])
	}
	out, err = invokeProjectTool(t, service, ctx, "project_get_finding", map[string]interface{}{
		"finding_id": findings[0].ID,
	})
	if err != nil ||
		!strings.Contains(out, "ID: "+findings[0].ID) ||
		!strings.Contains(out, "描述: id 参数可注入") ||
		!strings.Contains(out, "复现步骤: GET /x?id=1%20AND%201=1") ||
		!strings.Contains(out, "影响: 可读取数据库数据") {
		t.Fatalf("按 ID 查询漏洞详情失败: %q, err=%v", out, err)
	}
	otherAsset := database.Asset{
		ID:          "asset-other-scope",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "其他资产",
		Kind:        "url",
		Value:       "https://other.example",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := service.db.CreateAsset(ctx, otherAsset); err != nil {
		t.Fatalf("创建其他资产失败: %v", err)
	}
	scopedCtx := execctx.WithAssetID(ctx, otherAsset.ID)
	if _, err := invokeProjectTool(t, service, scopedCtx, "project_get_finding", map[string]interface{}{
		"finding_id": findings[0].ID,
	}); err == nil || !strings.Contains(err.Error(), "不在当前会话资产") {
		t.Fatalf("绑定资产会话不应读取其他资产漏洞，实际 err=%v", err)
	}
	projectScopedCtx := withMissionExecution(scopedCtx, missionExecution{
		Plan: missionPlan{ProjectScope: true},
	})
	if _, err := invokeProjectTool(t, service, projectScopedCtx, "project_get_finding", map[string]interface{}{
		"finding_id": findings[0].ID,
	}); err != nil {
		t.Fatalf("项目级任务应允许按 ID 查询其他资产漏洞: %v", err)
	}
	assets, err := service.db.ListProjectAssets(ctx, "project-tools", "user-1")
	foundTargetAsset := false
	for _, asset := range assets {
		if asset.Value == "https://a.com/x?id=1" {
			foundTargetAsset = true
		}
	}
	if err != nil || len(assets) != 2 || !foundTargetAsset {
		t.Fatalf("漏洞上报应自动登记并关联资产: %+v, err=%v", assets, err)
	}

	out, err = invokeProjectTool(t, service, ctx, "project_graph_overview", map[string]interface{}{})
	if err != nil || !strings.Contains(out, "[finding]") || !strings.Contains(out, "SQL 注入") {
		t.Fatalf("攻击路径总览缺少 finding 节点: %q, err=%v", out, err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "验证 WAF 绕过", "detail": "尝试编码绕过",
	}); err != nil {
		t.Fatalf("写入意图失败: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	intentID := ""
	for _, node := range nodes {
		if node.Kind == "intent" {
			intentID = node.ID
		}
	}
	if intentID == "" {
		t.Fatalf("未找到 intent 节点: %+v", nodes)
	}
	out, err = invokeProjectTool(t, service, ctx, "project_graph_node", map[string]interface{}{
		"node_id": intentID,
	})
	if err != nil || !strings.Contains(out, "验证 WAF 绕过") {
		t.Fatalf("节点详情异常: %q, err=%v", out, err)
	}
}

func TestProjectFindingDetailPreservesLongContent(t *testing.T) {
	longDescription := strings.Repeat("完整漏洞描述", 1200)
	longReproduction := strings.Repeat("curl --request GET https://app.example/api\n", 180)
	now := time.Now().UTC()
	output := formatProjectFindingDetail(database.Vulnerability{
		ID:                "vuln-long-detail",
		Title:             "长详情漏洞",
		Severity:          "high",
		Status:            "confirmed",
		Description:       longDescription,
		ReproductionSteps: longReproduction,
		Evidence:          "HTTP 200 与响应差异",
		CreatedAt:         now,
		UpdatedAt:         now,
	})
	if !strings.Contains(output, longDescription) || !strings.Contains(output, longReproduction) {
		t.Fatalf("精确漏洞详情不应截断描述或复现步骤，实际长度=%d", len(output))
	}
	if len(output) <= projectToolOutputLimit {
		t.Fatalf("长详情输出应突破普通列表截断上限，实际长度=%d", len(output))
	}
}

func TestProjectGetAggregatesDetailTools(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.tools = newProjectTools(service)
	inventory := service.ToolInventory(ctx)
	direct := map[string]InventoryTool{}
	for _, item := range inventory.Direct {
		direct[item.Name] = item
	}
	toolItem, ok := direct["project_get"]
	if !ok {
		t.Fatal("project_get 应直接暴露给模型")
	}
	for _, legacy := range []string{
		"project_asset_card",
		"project_get_finding",
		"project_graph_node",
	} {
		if _, exposed := direct[legacy]; exposed {
			t.Fatalf("旧详情工具 %s 不应继续直接暴露", legacy)
		}
	}
	var resourceParam *ToolParameter
	for index := range toolItem.Parameters {
		if toolItem.Parameters[index].Name == "resource" {
			resourceParam = &toolItem.Parameters[index]
			break
		}
	}
	if resourceParam == nil || !resourceParam.Required || len(resourceParam.Enum) != 3 {
		t.Fatalf("project_get.resource schema 异常: %+v", resourceParam)
	}
	if len(toolItem.Parameters) != 2 {
		t.Fatalf("project_get 只应暴露 resource/id 两个模型参数: %+v", toolItem.Parameters)
	}

	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-project-get",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "项目读取资产",
		Kind:        "domain",
		Value:       "get.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-project-get",
		ProjectID:   "project-tools",
		AssetID:     "asset-project-get",
		OwnerUserID: "user-1",
		Title:       "项目读取漏洞",
		Severity:    "high",
		Status:      "confirmed",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:        "node-project-get",
		ProjectID: "project-tools",
		AssetID:   "asset-project-get",
		Kind:      "intent",
		Title:     "项目读取节点",
		Status:    "open",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建图谱节点失败: %v", err)
	}

	for _, testCase := range []struct {
		name     string
		args     map[string]interface{}
		expected string
	}{
		{
			name: "asset",
			args: map[string]interface{}{
				"resource": "asset",
				"id":       "asset-project-get",
			},
			expected: "get.example.com",
		},
		{
			name: "finding",
			args: map[string]interface{}{
				"resource": "finding",
				"id":       "vuln-project-get",
			},
			expected: "项目读取漏洞",
		},
		{
			name: "graph_node",
			args: map[string]interface{}{
				"resource": "graph_node",
				"id":       "node-project-get",
			},
			expected: "项目读取节点",
		},
	} {
		output, err := invokeProjectTool(t, service, ctx, "project_get", testCase.args)
		if err != nil || !strings.Contains(output, testCase.expected) {
			t.Fatalf("project_get resource=%s 查询失败: %q %v", testCase.name, output, err)
		}
	}
}

func TestProjectGetRejectsInvalidParameters(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	for _, testCase := range []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{
			name: "缺少 resource",
			args: map[string]interface{}{},
			want: "resource 必须是",
		},
		{
			name: "未知 resource",
			args: map[string]interface{}{
				"resource": "unknown",
			},
			want: "resource 必须是",
		},
		{
			name: "资源类型不匹配",
			args: map[string]interface{}{
				"resource":   "finding",
				"finding_id": "finding-1",
				"asset_id":   "asset-1",
			},
			want: "不支持参数 asset_id",
		},
		{
			name: "finding 缺少 id",
			args: map[string]interface{}{
				"resource": "finding",
			},
			want: "resource=finding 的 id 不能为空",
		},
		{
			name: "graph_node 缺少 id",
			args: map[string]interface{}{
				"resource": "graph_node",
			},
			want: "resource=graph_node 的 id 不能为空",
		},
		{
			name: "id 与兼容字段冲突",
			args: map[string]interface{}{
				"resource":   "finding",
				"id":         "finding-a",
				"finding_id": "finding-b",
			},
			want: "id 与 finding_id 冲突",
		},
		{
			name: "未知字段",
			args: map[string]interface{}{
				"resource": "asset",
				"foo":      "bar",
			},
			want: "unknown field",
		},
	} {
		if _, err := invokeProjectTool(t, service, ctx, "project_get", testCase.args); err == nil ||
			!strings.Contains(err.Error(), testCase.want) {
			t.Fatalf("%s 应被拒绝，实际: %v", testCase.name, err)
		}
	}
}

func TestProjectToolValidation(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "越权资产", "severity": "high", "asset_id": "not-exist",
		"target": "https://a.com", "poc": "id=1", "evidence": "HTTP 500",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "http-probe")},
	})); err == nil || !strings.Contains(err.Error(), "不属于当前项目") {
		t.Fatalf("跨项目资产应被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", map[string]interface{}{
		"title": "非法严重度", "severity": "urgent",
	}); err == nil || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("非法严重度应被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_add_hint", map[string]interface{}{
		"title": "",
	}); err == nil || !strings.Contains(err.Error(), "title") {
		t.Fatalf("空标题应被拒绝: %v", err)
	}
}
