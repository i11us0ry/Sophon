package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestEvidenceReferenceErrorsIncludeFormatHint(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "evidence-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(db, config.Config{AgentMock: true}, nil, nil)
	if err != nil {
		t.Fatalf("创建服务失败: %v", err)
	}
	ctx := context.Background()

	if err := service.validateEvidenceReferences(ctx, "project-1", "user-1", []string{"invalid:abc"}, "low"); err == nil ||
		!strings.Contains(err.Error(), "tool:<工具执行ID>") {
		t.Fatalf("未知证据类型应返回格式提示: %v", err)
	}
	if err := service.validateEvidenceReferences(ctx, "project-1", "user-1", nil, "high"); err == nil ||
		!strings.Contains(err.Error(), "artifact:<artifact目录内文件路径>") {
		t.Fatalf("高等级漏洞缺少证据时应返回格式提示: %v", err)
	}
}
