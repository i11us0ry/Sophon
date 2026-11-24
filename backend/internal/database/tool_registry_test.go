package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestToolRegistryScopesAndRuntimePaths(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-registry.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-tools", OwnerUserID: "user-1", Name: "工具项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	items := []RegisteredTool{
		{
			ID: "tool-global", OwnerUserID: "user-1", Scope: ToolScopeGlobal,
			Name: "nuclei", Command: "/usr/local/bin/nuclei", Enabled: true,
		},
		{
			ID: "tool-project", OwnerUserID: "user-1", ProjectID: "project-tools",
			Scope: ToolScopeProject, Name: "suo5", Command: "/opt/tools/suo5",
			Env: map[string]string{"SUO5_HOME": "/opt/tools"}, Enabled: true,
		},
		{
			ID: "tool-session", OwnerUserID: "user-1", ProjectID: "project-tools",
			ConversationID: "conv-tools", Scope: ToolScopeSession,
			Name: "custom-probe", Command: "/tmp/custom-probe", Enabled: true,
		},
	}
	for _, item := range items {
		if _, err := db.UpsertRegisteredTool(ctx, item); err != nil {
			t.Fatalf("注册工具 %s 失败: %v", item.Name, err)
		}
	}
	if _, err := db.UpsertRegisteredTool(ctx, RegisteredTool{
		ID: "tool-foreign-global", OwnerUserID: "user-2", Scope: ToolScopeGlobal,
		Name: "nuclei", Command: "/tmp/malicious-nuclei", Enabled: true,
	}); err != nil {
		t.Fatalf("注册其他用户全局工具失败: %v", err)
	}
	visible, err := db.ListRegisteredTools(ctx, "user-1", "project-tools", "conv-tools")
	if err != nil || len(visible) != 3 {
		t.Fatalf("读取作用域工具失败: items=%+v err=%v", visible, err)
	}
	if visible[0].Scope != ToolScopeSession || visible[1].Scope != ToolScopeProject ||
		visible[2].Scope != ToolScopeGlobal {
		t.Fatalf("工具作用域顺序错误: %+v", visible)
	}

	for _, item := range []ToolRuntimePath{
		{
			ID: "path-global", OwnerUserID: "user-1", Scope: ToolScopeGlobal,
			Path: "/opt/global/bin",
		},
		{
			ID: "path-project", OwnerUserID: "user-1", ProjectID: "project-tools",
			Scope: ToolScopeProject, Path: "/opt/project/bin",
		},
		{
			ID: "path-session", OwnerUserID: "user-1", ProjectID: "project-tools",
			ConversationID: "conv-tools", Scope: ToolScopeSession,
			Path: "/opt/session/bin",
		},
	} {
		if _, err := db.UpsertToolRuntimePath(ctx, item); err != nil {
			t.Fatalf("注册 PATH 失败: %v", err)
		}
	}
	if _, err := db.UpsertToolRuntimePath(ctx, ToolRuntimePath{
		ID: "path-foreign-global", OwnerUserID: "user-2", Scope: ToolScopeGlobal,
		Path: "/tmp/malicious-bin",
	}); err != nil {
		t.Fatalf("注册其他用户全局 PATH 失败: %v", err)
	}
	paths, err := db.ListToolRuntimePaths(ctx, "user-1", "project-tools", "conv-tools")
	if err != nil || len(paths) != 3 ||
		paths[0].Path != "/opt/session/bin" ||
		paths[1].Path != "/opt/project/bin" ||
		paths[2].Path != "/opt/global/bin" {
		t.Fatalf("动态 PATH 顺序错误: paths=%+v err=%v", paths, err)
	}
	for _, item := range visible {
		if item.OwnerUserID != "user-1" {
			t.Fatalf("不应读取其他用户的全局工具: %+v", item)
		}
	}
	for _, item := range paths {
		if item.OwnerUserID != "user-1" {
			t.Fatalf("不应读取其他用户的全局 PATH: %+v", item)
		}
	}

	deleted, err := db.DeleteRegisteredTool(ctx, "tool-project", "user-1")
	if err != nil || !deleted {
		t.Fatalf("删除工具注册失败: deleted=%v err=%v", deleted, err)
	}
	deleted, err = db.DeleteToolRuntimePath(ctx, "path-project", "user-1")
	if err != nil || !deleted {
		t.Fatalf("删除 PATH 失败: deleted=%v err=%v", deleted, err)
	}
}

func TestDeleteProjectCleansToolRegistry(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "tool-registry-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-delete-tools", OwnerUserID: "user-1", Name: "删除工具项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertRegisteredTool(ctx, RegisteredTool{
		ID: "tool-delete", OwnerUserID: "user-1", ProjectID: "project-delete-tools",
		Scope: ToolScopeProject, Name: "demo", Command: "/tmp/demo", Enabled: true,
	}); err != nil {
		t.Fatalf("注册工具失败: %v", err)
	}
	if _, err := db.UpsertToolRuntimePath(ctx, ToolRuntimePath{
		ID: "path-delete", OwnerUserID: "user-1", ProjectID: "project-delete-tools",
		Scope: ToolScopeProject, Path: "/tmp/demo-bin",
	}); err != nil {
		t.Fatalf("注册 PATH 失败: %v", err)
	}
	if err := db.DeleteProject(ctx, "project-delete-tools", "user-1"); err != nil {
		t.Fatalf("删除项目失败: %v", err)
	}
	var registryCount int
	var pathCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tool_registry WHERE project_id = ?`,
		"project-delete-tools",
	).Scan(&registryCount); err != nil {
		t.Fatalf("统计工具注册失败: %v", err)
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tool_runtime_paths WHERE project_id = ?`,
		"project-delete-tools",
	).Scan(&pathCount); err != nil {
		t.Fatalf("统计动态 PATH 失败: %v", err)
	}
	if registryCount != 0 || pathCount != 0 {
		t.Fatalf("项目删除后工具数据残留: registry=%d paths=%d", registryCount, pathCount)
	}
}
