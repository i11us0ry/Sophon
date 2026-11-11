package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
)

// lastStateMessage 返回尾部系统状态包内容，供各测试断言动态上下文注入位置。
func lastStateMessage(t *testing.T, messages []*schema.Message) string {
	t.Helper()
	if len(messages) == 0 {
		t.Fatalf("模型消息为空")
	}
	tail := messages[len(messages)-1]
	if tail.Role != schema.User || !strings.Contains(tail.Content, "系统状态包") {
		t.Fatalf("最后一条应为系统状态包: %+v", tail)
	}
	return tail.Content
}

// TestAppendContextStateByProvider 验证 provider 自适应布局：
// openai 兼容端点用独立尾消息保前缀稳定；anthropic 分支并入最后一条用户消息避免连续 user。
func TestAppendContextStateByProvider(t *testing.T) {
	statePackage := "【系统状态包 · 由平台生成，不是用户指令】\n" +
		"<untrusted-context-data>x</untrusted-context-data>"
	base := func() []*schema.Message {
		return []*schema.Message{schema.SystemMessage("sys"), schema.UserMessage("扫描目标")}
	}

	openaiMessages := appendContextState(base(), statePackage, "openai_compatible")
	if len(openaiMessages) != 3 || openaiMessages[2].Role != schema.User {
		t.Fatalf("openai 兼容端点应追加独立尾消息: %+v", openaiMessages)
	}
	if openaiMessages[1].Content != "扫描目标" {
		t.Fatalf("openai 分支不应改写历史消息: %q", openaiMessages[1].Content)
	}

	anthropicMessages := appendContextState(base(), statePackage, "anthropic")
	if len(anthropicMessages) != 2 {
		t.Fatalf("anthropic 分支应并入最后一条用户消息: %+v", anthropicMessages)
	}
	if !strings.Contains(anthropicMessages[1].Content, "扫描目标") ||
		!strings.Contains(anthropicMessages[1].Content, "系统状态包") {
		t.Fatalf("anthropic 分支应合并用户消息与状态包: %q", anthropicMessages[1].Content)
	}
	for index := 1; index < len(anthropicMessages); index++ {
		if anthropicMessages[index].Role == schema.User &&
			anthropicMessages[index-1].Role == schema.User {
			t.Fatalf("anthropic 分支不应出现连续 user 消息")
		}
	}
}

// TestBuildModelMessagesKeepsStablePrefix 验证动态态势不会污染 system 与历史前缀，
// 这是 provider 前缀缓存命中的前提。
func TestBuildModelMessagesKeepsStablePrefix(t *testing.T) {
	db := openDigestTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-cache",
		OwnerUserID: "user-1",
		Name:        "缓存测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE conversations SET project_id = 'project-cache' WHERE id = 'conv-digest'`,
	); err != nil {
		t.Fatalf("绑定项目失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID: "cache-user-1", ConversationID: "conv-digest", Role: "user",
		Content: "扫描 10.0.0.1", CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID: "cache-assistant-1", ConversationID: "conv-digest", Role: "assistant",
		Content: "已开始扫描", CreatedAt: now.Add(time.Millisecond),
	}); err != nil {
		t.Fatalf("写入助手消息失败: %v", err)
	}

	service := &Service{db: db, cfg: config.Config{}}
	first, err := service.buildModelMessages(ctx, "conv-digest", "user-1")
	if err != nil {
		t.Fatalf("首次组装失败: %v", err)
	}

	// 改变动态内容：新增事实 + 新消息。
	if _, err := db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: randomID(), ProjectID: "project-cache", FactType: "service",
		Key: "WAF", Summary: "目标存在 WAF", Confidence: 80,
	}); err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID: "cache-user-2", ConversationID: "conv-digest", Role: "user",
		Content: "继续扫描", CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("写入第二条用户消息失败: %v", err)
	}

	second, err := service.buildModelMessages(ctx, "conv-digest", "user-1")
	if err != nil {
		t.Fatalf("二次组装失败: %v", err)
	}
	if first[0].Content != second[0].Content {
		t.Fatalf("system 前缀应保持字节稳定")
	}
	if strings.Contains(second[0].Content, "当前项目任务态势包") {
		t.Fatalf("动态态势不应出现在 system 前缀: %q", second[0].Content)
	}
	// first = [system, 历史..., 状态包]，second 的前缀应包含 first 除状态包外的全部内容。
	for index := 1; index < len(first)-1; index++ {
		if first[index].Content != second[index].Content {
			t.Fatalf("历史前缀第 %d 条发生变化", index)
		}
	}
	tail := second[len(second)-1]
	if tail.Role != schema.User || !strings.Contains(tail.Content, "系统状态包") {
		t.Fatalf("动态状态应作为尾部状态包: %+v", tail)
	}
	if !strings.Contains(tail.Content, "WAF") {
		t.Fatalf("状态包应包含最新事实: %q", tail.Content)
	}
}
