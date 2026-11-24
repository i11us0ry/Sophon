package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestUnknownToolHandlerRecoversDirectoryList(t *testing.T) {
	service := &Service{}
	result, err := service.unknownToolHandler(
		context.Background(),
		"directory_list",
		`{"path":"/tmp"}`,
	)
	if err != nil {
		t.Fatalf("未知工具处理不应返回错误: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusError || header.ErrorClass != toolErrorInvalidArguments {
		t.Fatalf("未知工具协议头异常: %+v body=%s", header, body)
	}
	for _, want := range []string{
		"directory_list",
		"不存在",
		"未执行",
		"exec",
		"ls -la",
		`/tmp`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("未知工具提示缺少 %q：%s", want, body)
		}
	}
}

func TestUnknownToolHandlerReportsDisabledTool(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "unknown-tool.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.UpsertMCPToolSettings(context.Background(), []database.MCPToolSetting{{
		ServerName: "sophon-tool-runner",
		ToolName:   "directory_list",
		Enabled:    false,
		Capability: "read",
		UpdatedAt:  time.Now().UTC(),
	}}); err != nil {
		t.Fatalf("写入工具设置失败: %v", err)
	}

	service := &Service{db: db}
	result, err := service.unknownToolHandler(
		context.Background(),
		"directory_list",
		`{"path":"/tmp"}`,
	)
	if err != nil {
		t.Fatalf("停用工具处理不应返回错误: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusBlocked || header.ErrorClass != toolErrorPolicy {
		t.Fatalf("停用工具协议头异常: %+v body=%s", header, body)
	}
	if !strings.Contains(body, "停用") || !strings.Contains(body, "未执行") {
		t.Fatalf("停用工具提示异常: %s", body)
	}
}
