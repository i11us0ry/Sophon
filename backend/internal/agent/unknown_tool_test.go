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
	for _, want := range []string{
		"directory_list",
		"不存在",
		"未执行",
		"exec",
		"ls -la",
		`/tmp`,
	} {
		if !strings.Contains(result, want) {
			t.Fatalf("未知工具提示缺少 %q：%s", want, result)
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
	if !strings.Contains(result, "停用") || !strings.Contains(result, "未执行") {
		t.Fatalf("停用工具提示异常: %s", result)
	}
}
