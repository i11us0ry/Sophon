package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmitterWritesMetadataOnlyEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observability", "events.jsonl")
	emitter, err := New(Config{Enabled: true, JSONLPath: path, MaxFileMB: 1, SampleRate: 1})
	if err != nil {
		t.Fatalf("创建事件输出器失败: %v", err)
	}
	t.Cleanup(func() { _ = emitter.Close() })

	emitter.Emit(Event{
		EventType:      TypeToolStarted,
		UserID:         "user-1",
		ProjectID:      "project-1",
		ConversationID: "conversation-1",
		ToolName:       "sqlmap",
		ServerName:     "sophon-tool-runner",
	})
	emitter.Emit(Event{
		EventType:      TypeToolDecision,
		ToolName:       "sqlmap",
		PolicyDecision: "require_approval",
		Capability:     "intrusive",
		DurationMS:     12,
	})
	emitter.Emit(Event{
		EventType:     TypeToolFailed,
		ToolName:      "exec",
		ErrorCategory: "timeout",
		Success:       Bool(false),
		Detail:        "执行超时",
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取事件文件失败: %v", err)
	}
	content := string(raw)
	for _, marker := range []string{`"event_type":"tool.started"`, `"tool_name":"sqlmap"`, `"policy_decision":"require_approval"`} {
		if !strings.Contains(content, marker) {
			t.Fatalf("事件文件缺少 %s: %s", marker, content)
		}
	}
	// 事件模型本身不携带提示词、命令与工具参数，避免敏感数据外泄。
	for _, secret := range []string{"command", "arguments", "prompt", "api_key", "cookie", "password"} {
		if strings.Contains(content, secret) {
			t.Fatalf("事件流不应包含敏感字段 %s: %s", secret, content)
		}
	}

	metrics := emitter.Metrics()
	if metrics.EventsTotal != 3 {
		t.Fatalf("事件计数错误: %d", metrics.EventsTotal)
	}
	if metrics.FailuresTotal != 1 || metrics.ApprovalsTotal != 1 || metrics.DeniedTotal != 0 {
		t.Fatalf("聚合指标错误: %#v", metrics)
	}
	if metrics.Tools["sqlmap"] != 2 || metrics.ByType[TypeToolFailed] != 1 {
		t.Fatalf("按工具/类型聚合错误: %#v", metrics)
	}
	if metrics.FileBytes == 0 {
		t.Fatalf("事件文件大小统计错误")
	}

	recent := emitter.Recent(2)
	if len(recent) != 2 || recent[1].EventType != TypeToolFailed {
		t.Fatalf("最近事件顺序错误: %#v", recent)
	}
}

func TestEmitterDisabledIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	emitter, err := New(Config{Enabled: false, JSONLPath: path})
	if err != nil {
		t.Fatalf("关闭状态不应报错: %v", err)
	}
	emitter.Emit(Event{EventType: TypeRunStarted})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("关闭状态不应写文件: %v", err)
	}
	if metrics := emitter.Metrics(); metrics.Enabled || metrics.EventsTotal != 0 {
		t.Fatalf("关闭状态指标应为空: %#v", metrics)
	}
	if events := emitter.Recent(10); len(events) != 0 {
		t.Fatalf("关闭状态不应有最近事件: %#v", events)
	}
}

func TestEmitterWithoutPathFailsClosed(t *testing.T) {
	if _, err := New(Config{Enabled: true, JSONLPath: "  "}); err == nil {
		t.Fatalf("开启事件流但缺少路径时应返回错误")
	}
}

func TestErrorCategory(t *testing.T) {
	cases := map[string]string{
		"context deadline exceeded":              "timeout",
		"Policy Engine 拒绝执行 sqlmap":              "policy_denied",
		"tool directory_list not found":          "not_found",
		"status code: 502 bad gateway":           "gateway",
		"connection refused":                     "transient_network",
		"status code: 429 too many requests":     "rate_limit",
		"invalid credential or status code: 401": "credential_missing",
	}
	for message, want := range cases {
		if got := ErrorCategory(message); got != want {
			t.Fatalf("错误分类 %q 期望 %s，实际 %s", message, want, got)
		}
	}
}
