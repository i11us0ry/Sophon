package agent

import (
	"path/filepath"
	"testing"

	"sophon/internal/config"
)

func TestAgentWorkspacePathsSeparateProjects(t *testing.T) {
	root := t.TempDir()
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{
			ArtifactRoot: root,
			Categories: map[string]config.StorageCategoryConfig{
				"workspace": {Enabled: true, Path: "tmp/workspace"},
			},
		},
	}}
	projectA, err := service.agentWorkspacePathsFor("project-a", "conversation-1")
	if err != nil {
		t.Fatalf("解析项目 A 工作区失败: %v", err)
	}
	projectB, err := service.agentWorkspacePathsFor("project-b", "conversation-1")
	if err != nil {
		t.Fatalf("解析项目 B 工作区失败: %v", err)
	}
	if projectA.ConversationRoot == projectB.ConversationRoot {
		t.Fatalf("不同项目不应共享会话工作区")
	}
	wantA := filepath.Join(
		root,
		"tmp",
		"workspace",
		"projects",
		"project-a",
		"conversations",
		"conversation-1",
	)
	if projectA.ConversationRoot != wantA {
		t.Fatalf("项目工作区路径错误: got=%s want=%s", projectA.ConversationRoot, wantA)
	}
}

func TestAgentWorkspacePathsRejectMissingProject(t *testing.T) {
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{
			ArtifactRoot: t.TempDir(),
			Categories: map[string]config.StorageCategoryConfig{
				"workspace": {Enabled: true, Path: "tmp/workspace"},
			},
		},
	}}
	if _, err := service.agentWorkspacePathsFor("", "conversation-1"); err == nil {
		t.Fatalf("缺少项目 ID 时必须拒绝创建未隔离工作区")
	}
}

func TestAgentWorkspacePathsDoNotTreatReservedDirAsLegacyConversation(t *testing.T) {
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{
			ArtifactRoot: t.TempDir(),
			Categories: map[string]config.StorageCategoryConfig{
				"workspace": {Enabled: true, Path: "tmp/workspace"},
			},
		},
	}}
	paths, err := service.agentWorkspacePathsFor("project-a", workspaceProjectsDir)
	if err != nil {
		t.Fatalf("解析保留目录名失败: %v", err)
	}
	if paths.LegacyRoot != "" {
		t.Fatalf("保留目录不能作为旧会话工作区: %s", paths.LegacyRoot)
	}
}
