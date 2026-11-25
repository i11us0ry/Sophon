package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func createProactiveUpdateConversation(t *testing.T, service *Service, suffix string) (*database.Project, *database.Conversation) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	project := &database.Project{
		ID:          "project-" + suffix,
		OwnerUserID: "user-1",
		Name:        "Proactive " + suffix,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := service.db.CreateProject(ctx, *project); err != nil {
		t.Fatal(err)
	}
	conversation := &database.Conversation{
		ID:          "conv-" + suffix,
		OwnerUserID: "user-1",
		ProjectID:   project.ID,
		Title:       "Proactive " + suffix,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := service.db.CreateConversation(ctx, *conversation); err != nil {
		t.Fatal(err)
	}
	return project, conversation
}

func proactiveTestContext(project *database.Project, conversation *database.Conversation) context.Context {
	ctx := execctx.WithConversationID(context.Background(), conversation.ID)
	ctx = execctx.WithUserID(ctx, project.OwnerUserID)
	ctx = execctx.WithProjectID(ctx, project.ID)
	return ctx
}

func TestProcessBackgroundUpdateCreatesProactiveMessage(t *testing.T) {
	service := newSubAgentTestService(t)
	service.model = nil
	project, conversation := createProactiveUpdateConversation(t, service, "message")
	ctx := context.Background()
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]interface{}{
		"summary": "发现新的已确认漏洞",
	})
	if err := service.db.EnqueueBackgroundUpdate(ctx, database.BackgroundUpdateEvent{
		ID:             "update-message-1",
		ConversationID: conversation.ID,
		ProjectID:      project.ID,
		OwnerUserID:    project.OwnerUserID,
		Kind:           "finding_confirmed",
		Priority:       100,
		DedupeKey:      "finding:test",
		PayloadJSON:    string(payload),
		NotBefore:      now.Add(-time.Second),
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	if !service.processBackgroundUpdateConversation(ctx, conversation.ID, now) {
		t.Fatal("后台更新未被处理")
	}
	messages, err := service.db.GetMessages(ctx, conversation.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Role != "assistant" ||
		messages[0].MessageKind != "proactive" ||
		!strings.Contains(messages[0].Content, "后台进展") ||
		!strings.Contains(messages[0].Content, "漏洞") {
		t.Fatalf("主动消息错误: %+v", messages)
	}
	details, err := service.db.ListProcessDetails(ctx, conversation.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, detail := range details {
		if detail.EventType == "main_agent.proactive" && detail.MessageID == messages[0].ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("缺少 main_agent.proactive 事件: %+v", details)
	}
	if count, err := service.db.CountPendingBackgroundUpdates(ctx, conversation.ID); err != nil || count != 0 {
		t.Fatalf("通知事件未完成: count=%d err=%v", count, err)
	}
}

func TestProactiveUpdateUsageIsSeparateFromContext(t *testing.T) {
	service := newSubAgentTestService(t)
	service.model = &vulnerabilityReviewTestModel{
		content: "后台进展\n后台摘要已生成",
	}
	project, conversation := createProactiveUpdateConversation(t, service, "usage")
	ctx := context.Background()
	now := time.Now().UTC()
	if err := service.db.EnqueueBackgroundUpdate(ctx, database.BackgroundUpdateEvent{
		ID:             "update-usage-1",
		ConversationID: conversation.ID,
		ProjectID:      project.ID,
		OwnerUserID:    project.OwnerUserID,
		Kind:           "finding_confirmed",
		Priority:       100,
		DedupeKey:      "finding:usage",
		PayloadJSON:    `{"summary":"测试事件"}`,
		NotBefore:      now.Add(-time.Second),
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	if !service.processBackgroundUpdateConversation(ctx, conversation.ID, now) {
		t.Fatal("后台更新未被处理")
	}
	messages, err := service.db.GetContextMessages(ctx, conversation.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Fatalf("后台进展不应进入模型上下文: %+v", messages)
	}
	var count int
	if err := service.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM token_usage WHERE conversation_id = ? AND kind = 'proactive'`,
		conversation.ID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("后台播报 Token 未按 proactive 类型单独记录")
	}
}

func TestProactiveToolUpdateDedupe(t *testing.T) {
	service := newSubAgentTestService(t)
	project, conversation := createProactiveUpdateConversation(t, service, "tool")
	ctx := execctx.WithSubagent(proactiveTestContext(project, conversation), execctx.SubagentInfo{
		ID: "worker-1", Kind: "worker", HypothesisID: "hyp-1",
	})
	result := `{
		"ok":true,
		"status":"generated",
		"artifact_id":"artifact-1",
		"directory":"/tmp/artifact-1",
		"shell_file":"/tmp/artifact-1/godzilla_csharp_aspx.aspx",
		"client_config":"/tmp/artifact-1/client-config.json",
		"verify_python":"/tmp/artifact-1/verify.py",
		"request_http":"/tmp/artifact-1/request.http",
		"report":"/tmp/artifact-1/report.md",
		"metadata":"/tmp/artifact-1/metadata.json",
		"next_action":"upload_shell_then_run_verify_python",
		"metadata_payload":{
			"family":"godzilla",
			"target_url":"https://target.example/shell.aspx",
			"language":"csharp",
			"container":"aspx",
			"cryptor":"CSharpAesBase64",
			"shell_sha256":"52d844eca498d93560d8bda407428aa585ff3f3e2722a125fddf04f20f36a984",
			"shell_bytes":1409
		}
	}`
	service.maybeEnqueueProactiveToolUpdate(ctx, "payload_factory", result)
	service.maybeEnqueueProactiveToolUpdate(ctx, "payload_factory", result)
	events, err := service.db.ClaimBackgroundUpdatesForConversation(
		context.Background(),
		conversation.ID,
		time.Now().UTC().Add(5*time.Second),
		10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "artifact_ready" {
		t.Fatalf("artifact 事件去重失败: %+v", events)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(events[0].PayloadJSON), &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"clientConfig", "verifyPython", "requestHttp", "metadata_payload"} {
		if payload[key] == nil {
			t.Fatalf("artifact 事件缺少字段 %s: %+v", key, payload)
		}
	}
	summary := proactiveFallbackSummary([]proactivePromptEvent{{
		Kind: events[0].Kind, CreatedAt: nowString(), Payload: payload,
	}})
	for _, want := range []string{
		"关键详情",
		"客户端配置：/tmp/artifact-1/client-config.json",
		"验证脚本：/tmp/artifact-1/verify.py",
		"使用方式：客户端加载配置 /tmp/artifact-1/client-config.json",
		"目标 https://target.example/shell.aspx",
		"容器 aspx",
		"加密器 CSharpAesBase64",
		"SHA-256：52d844",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("artifact 通用详情缺少 %q: %s", want, summary)
		}
	}
	if err := service.db.CompleteBackgroundUpdates(
		context.Background(),
		[]string{events[0].ID},
		database.BackgroundUpdateSuppressed,
	); err != nil {
		t.Fatal(err)
	}
}

func TestProactiveFindingEventAndFallback(t *testing.T) {
	service := newSubAgentTestService(t)
	project, conversation := createProactiveUpdateConversation(t, service, "finding")
	ctx := proactiveTestContext(project, conversation)
	service.enqueueFindingProactiveUpdate(ctx, &database.Vulnerability{
		ID:                "finding-1",
		ProjectID:         project.ID,
		OwnerUserID:       project.OwnerUserID,
		Title:             "测试任意文件读取",
		Severity:          "high",
		Status:            "confirmed",
		VulnerabilityType: "File Upload",
		HTTPMethod:        "POST",
		Parameter:         "file",
		Preconditions:     "需要普通账户",
		ReproductionSteps: "POST /upload HTTP/1.1\nHost: target.example\n\n上传 test.aspx 后访问 /upload/test.aspx",
		Description:       "上传接口未校验文件类型，可写入可执行文件",
		Evidence:          "HTTP 200，返回上传路径 /upload/test.aspx",
		EvidenceRefs:      []string{"tool:upload-test"},
		Impact:            "可向服务器写入任意文件",
		Recommendation:    "限制文件类型并禁止上传目录执行脚本",
		VerificationState: "verified",
		Confidence:        95,
		Exploitability:    "已验证文件写入",
		TestTechnique:     "multipart_file_upload",
		Target:            "https://target.example",
	})
	events, err := service.db.ClaimBackgroundUpdatesForConversation(
		context.Background(),
		conversation.ID,
		time.Now().UTC().Add(5*time.Second),
		10,
	)
	if err != nil || len(events) != 1 {
		t.Fatalf("漏洞通知事件错误: %+v err=%v", events, err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(events[0].PayloadJSON), &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"vulnerabilityType", "httpMethod", "parameter", "preconditions",
		"reproductionSteps", "evidence", "evidenceRefs", "impact", "recommendation",
	} {
		if payload[key] == nil {
			t.Fatalf("漏洞事件缺少字段 %s: %+v", key, payload)
		}
	}
	summary := proactiveFallbackSummary([]proactivePromptEvent{{
		Kind: events[0].Kind, CreatedAt: nowString(), Payload: payload,
	}})
	for _, want := range []string{
		"后台进展", "关键详情", "测试任意文件读取", "对象：https://target.example",
		"类型：File Upload", "入口：POST；file", "证据：HTTP 200",
		"影响：可向服务器写入任意文件", "修复建议：限制文件类型",
		"证据引用：tool:upload-test",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("漏洞通用详情缺少 %q: %s", want, summary)
		}
	}
}

func TestProactiveDetailsSupportUnknownEvents(t *testing.T) {
	events := []proactivePromptEvent{{
		Kind: "custom_checkpoint",
		Payload: map[string]interface{}{
			"summary":      "证据归档完成",
			"object":       "project-alpha",
			"checkpoint":   "evidence-03",
			"record_count": 12,
			"future_meta": map[string]interface{}{
				"owner": "team-a",
			},
		},
	}}
	content := appendProactiveDetails("后台进展\n已生成证据目录", events)
	for _, want := range []string{
		"关键详情", "证据归档完成", "对象：project-alpha",
		"checkpoint=evidence-03", "record_count=12", "owner=team-a",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("未知事件通用详情缺少 %q: %s", want, content)
		}
	}
	if strings.Count(content, "关键详情：") != 1 {
		t.Fatalf("关键详情不应重复追加: %s", content)
	}
}

func TestProactiveUpdateWaitsForActiveMainRun(t *testing.T) {
	service := newSubAgentTestService(t)
	service.model = nil
	project, conversation := createProactiveUpdateConversation(t, service, "active-run")
	ctx := context.Background()
	now := time.Now().UTC()
	if err := service.db.CreateAgentRun(ctx, database.AgentRun{
		ID:                 "run-active",
		ConversationID:     conversation.ID,
		AssistantMessageID: "message-active",
		Status:             database.AgentRunStatusRunning,
		AgentMode:          database.AgentRunModeDeep,
		StartedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.db.EnqueueBackgroundUpdate(ctx, database.BackgroundUpdateEvent{
		ID:             "update-active-run",
		ConversationID: conversation.ID,
		ProjectID:      project.ID,
		OwnerUserID:    project.OwnerUserID,
		Kind:           "worker_result",
		Priority:       100,
		DedupeKey:      "worker:active",
		PayloadJSON:    `{"summary":"worker result"}`,
		NotBefore:      now.Add(-time.Second),
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	if service.processBackgroundUpdateConversation(ctx, conversation.ID, now) {
		t.Fatal("主 Agent 运行中不应生成主动消息")
	}
	messages, err := service.db.GetMessages(ctx, conversation.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Fatalf("主 Agent 运行中不应写消息: %+v", messages)
	}
	if count, err := service.db.CountPendingBackgroundUpdates(ctx, conversation.ID); err != nil || count != 1 {
		t.Fatalf("通知事件应释放为 pending: count=%d err=%v", count, err)
	}
}

func TestProactiveToolUpdateIgnoresMainAgent(t *testing.T) {
	service := newSubAgentTestService(t)
	project, conversation := createProactiveUpdateConversation(t, service, "main-tool")
	ctx := proactiveTestContext(project, conversation)
	service.maybeEnqueueProactiveToolUpdate(
		ctx,
		"payload_factory",
		`{"ok":true,"status":"generated","artifact_id":"artifact-main"}`,
	)
	if count, err := service.db.CountPendingBackgroundUpdates(ctx, conversation.ID); err != nil || count != 0 {
		t.Fatalf("主 Agent 工具调用不应创建后台通知: count=%d err=%v", count, err)
	}
}

func TestProactiveFallbackRedactsSecrets(t *testing.T) {
	summary := proactiveFallbackSummary([]proactivePromptEvent{{
		Kind: "worker_result",
		Payload: map[string]interface{}{
			"summary": "password=supersecret token=abc123",
		},
	}})
	for _, secret := range []string{"supersecret", "abc123"} {
		if strings.Contains(summary, secret) {
			t.Fatalf("降级摘要泄漏敏感值: %s", summary)
		}
	}
}

func TestResolvedHITLNotificationIsSuppressed(t *testing.T) {
	service := newSubAgentTestService(t)
	service.model = nil
	project, conversation := createProactiveUpdateConversation(t, service, "resolved-hitl")
	ctx := context.Background()
	now := time.Now().UTC()
	if err := service.db.CreateHITLRequest(ctx, database.HITLRequest{
		ID:             "hitl-approved",
		ConversationID: conversation.ID,
		UserID:         project.OwnerUserID,
		ToolName:       "exec",
		Status:         "approved",
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.db.DecideHITLRequest(
		ctx,
		"hitl-approved",
		project.OwnerUserID,
		true,
		"approved before notification",
		project.OwnerUserID,
	); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]interface{}{"requestId": "hitl-approved"})
	if err := service.db.EnqueueBackgroundUpdate(ctx, database.BackgroundUpdateEvent{
		ID:             "update-resolved-hitl",
		ConversationID: conversation.ID,
		ProjectID:      project.ID,
		OwnerUserID:    project.OwnerUserID,
		Kind:           "interaction_required",
		Priority:       100,
		DedupeKey:      "hitl:approved",
		PayloadJSON:    string(payload),
		NotBefore:      now.Add(-time.Second),
		CreatedAt:      now,
	}); err != nil {
		t.Fatal(err)
	}
	if !service.processBackgroundUpdateConversation(ctx, conversation.ID, now) {
		t.Fatal("过期审批事件应被消费")
	}
	messages, err := service.db.GetMessages(ctx, conversation.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Fatalf("已处理审批不应生成主动消息: %+v", messages)
	}
	if count, err := service.db.CountPendingBackgroundUpdates(ctx, conversation.ID); err != nil || count != 0 {
		t.Fatalf("过期审批事件应被抑制: count=%d err=%v", count, err)
	}
}

func nowString() string {
	return time.Now().UTC().Format(time.RFC3339)
}
