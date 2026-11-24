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

func TestProactiveToolUpdateDedupe(t *testing.T) {
	service := newSubAgentTestService(t)
	project, conversation := createProactiveUpdateConversation(t, service, "tool")
	ctx := execctx.WithSubagent(proactiveTestContext(project, conversation), execctx.SubagentInfo{
		ID: "worker-1", Kind: "worker", HypothesisID: "hyp-1",
	})
	result := `{"ok":true,"status":"generated","artifact_id":"artifact-1","directory":"/tmp/artifact-1"}`
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
		VerificationState: "verified",
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
	summary := proactiveFallbackSummary([]proactivePromptEvent{{
		Kind: events[0].Kind, CreatedAt: nowString(), Payload: payload,
	}})
	if !strings.Contains(summary, "后台进展") || !strings.Contains(summary, "测试任意文件读取") {
		t.Fatalf("降级摘要错误: %s", summary)
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
