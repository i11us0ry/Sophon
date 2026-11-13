package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/cloudwego/eino/components/tool"
)

func TestProjectContextToolsRespectProjectBoundary(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	root := t.TempDir()
	service.cfg.Storage.ArtifactRoot = root
	now := time.Now().UTC()
	for _, conversation := range []database.Conversation{
		{ID: "conv-source-tools", OwnerUserID: "user-1", ProjectID: "project-tools", Title: "源码", CreatedAt: now, UpdatedAt: now},
	} {
		if err := service.db.CreateConversation(ctx, conversation); err != nil {
			t.Fatalf("创建项目对话失败: %v", err)
		}
	}
	if err := service.db.CreateProject(ctx, database.Project{
		ID: "project-other-tools", OwnerUserID: "user-1", Name: "其他项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	if err := service.db.CreateConversation(ctx, database.Conversation{
		ID: "conv-other-tools", OwnerUserID: "user-1", ProjectID: "project-other-tools",
		Title: "其他源码", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目对话失败: %v", err)
	}
	sourcePath := filepath.Join(root, "tmp", "workspace", "conv-source-tools", "src", "WebSite", "Login.cs")
	otherPath := filepath.Join(root, "tmp", "workspace", "conv-other-tools", "Other.cs")
	for _, path := range []string{sourcePath, otherPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
		if err := os.WriteFile(path, []byte("class Demo {}"), 0o600); err != nil {
			t.Fatalf("写入文件失败: %v", err)
		}
	}
	if err := service.db.AddMessage(ctx, database.Message{
		ID: "msg-source-tools", ConversationID: "conv-source-tools",
		Role: "user", Content: "源码上传点在这里", CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入历史消息失败: %v", err)
	}

	searchTool := newSearchProjectHistoryTool(service).(tool.InvokableTool)
	output, err := searchTool.InvokableRun(ctx, `{"query":"上传点","limit":10}`)
	if err != nil || !strings.Contains(output, "msg-source-tools") {
		t.Fatalf("历史搜索工具异常: %s err=%v", output, err)
	}

	discoverTool := newDiscoverProjectSourcesTool(service).(tool.InvokableTool)
	output, err = discoverTool.InvokableRun(ctx, `{"query":"Login.cs","limit":20}`)
	if err != nil || !strings.Contains(output, sourcePath) {
		t.Fatalf("文件发现工具缺少目标源码: %s err=%v", output, err)
	}
	if strings.Contains(output, otherPath) || strings.Contains(output, "Other.cs") {
		t.Fatalf("文件发现工具越出当前项目: %s", output)
	}
}
