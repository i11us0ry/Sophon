package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/intercept"
)

func TestToolInterceptorEnforcesPolicyEngine(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "tool-policy.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-tool-policy", OwnerUserID: "user-1", Name: "工具策略",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conversation-tool-policy", OwnerUserID: "user-1",
		ProjectID: "project-tool-policy", Title: "工具策略",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if err := db.CreateInterceptRule(ctx, database.InterceptRule{
		ID: "allow-exec-read", Name: "allow read exec", Enabled: true, Priority: 200,
		MatchTarget: intercept.TargetToolInput, MatchType: intercept.MatchString,
		Pattern: "ls -la", Action: intercept.ActionAllow, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建放行规则失败: %v", err)
	}

	workspaceRoot := t.TempDir()
	service := &Service{
		db: db,
		cfg: config.Config{
			HITLEnabled: true,
			HITLTools:   "exec",
			Storage: config.StorageConfig{
				ArtifactRoot: workspaceRoot,
				Categories: map[string]config.StorageCategoryConfig{
					"workspace": {Enabled: true, Path: "tmp/workspace"},
				},
			},
		},
	}
	interceptor := service.toolInterceptor(
		"conversation-tool-policy",
		"user-1",
		nil,
	)
	execArgs := map[string]interface{}{"command": "ls -la"}
	if err := interceptor(
		ctx,
		"sophon-tool-runner",
		"exec",
		execArgs,
	); err != nil {
		t.Fatalf("只读 exec 应通过 Policy Engine: %v", err)
	}
	wantWorkspace := filepath.Join(workspaceRoot, "tmp", "workspace", "conversation-tool-policy")
	if execArgs["_sophon_workspace"] != wantWorkspace {
		t.Fatalf("未注入会话工作区: %#v", execArgs)
	}
	if info, err := os.Stat(wantWorkspace); err != nil || !info.IsDir() {
		t.Fatalf("会话工作区未创建: %v", err)
	}
	err = interceptor(
		ctx,
		"sophon-tool-runner",
		"exec",
		map[string]interface{}{"command": "rm -rf /"},
	)
	if err == nil || !strings.Contains(err.Error(), "拦截设置") {
		t.Fatalf("灾难性删除应被拦截规则直接拒绝，实际 err=%v", err)
	}
}
