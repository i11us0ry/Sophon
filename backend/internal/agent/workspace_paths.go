package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sophon/internal/execctx"
)

const (
	workspaceProjectsDir      = "projects"
	workspaceConversationsDir = "conversations"
)

type agentWorkspacePaths struct {
	ProjectID        string
	ProjectRoot      string
	ConversationRoot string
	LegacyRoot       string
}

func (s *Service) agentWorkspacePaths(
	ctx context.Context,
	conversationID string,
) (agentWorkspacePaths, error) {
	conversationID = strings.TrimSpace(conversationID)
	if err := validateWorkspacePathPart(conversationID, "会话 ID"); err != nil {
		return agentWorkspacePaths{}, err
	}
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if projectID == "" && s != nil && s.db != nil && userID != "" {
		conversation, err := s.db.GetConversation(ctx, conversationID, userID)
		if err != nil {
			return agentWorkspacePaths{}, fmt.Errorf("读取会话所属项目失败: %w", err)
		}
		projectID = strings.TrimSpace(conversation.ProjectID)
	}
	if err := validateWorkspacePathPart(projectID, "项目 ID"); err != nil {
		return agentWorkspacePaths{}, err
	}
	return s.agentWorkspacePathsFor(projectID, conversationID)
}

func (s *Service) agentWorkspacePathsFor(
	projectID string,
	conversationID string,
) (agentWorkspacePaths, error) {
	if s == nil {
		return agentWorkspacePaths{}, fmt.Errorf("工作区服务不可用")
	}
	if err := validateWorkspacePathPart(projectID, "项目 ID"); err != nil {
		return agentWorkspacePaths{}, err
	}
	if err := validateWorkspacePathPart(conversationID, "会话 ID"); err != nil {
		return agentWorkspacePaths{}, err
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return agentWorkspacePaths{}, fmt.Errorf("存储根目录未配置")
	}
	categoryPath := "tmp/workspace"
	if category, ok := s.configSnapshot().Storage.Categories["workspace"]; ok &&
		strings.TrimSpace(category.Path) != "" {
		categoryPath = strings.TrimSpace(category.Path)
	}
	categoryRoot := filepath.Join(root, filepath.FromSlash(categoryPath))
	projectRoot := filepath.Join(
		categoryRoot,
		workspaceProjectsDir,
		projectID,
	)
	legacyRoot := filepath.Join(categoryRoot, conversationID)
	if conversationID == workspaceProjectsDir || conversationID == "mcp-runtime" {
		legacyRoot = ""
	}
	return agentWorkspacePaths{
		ProjectID:   projectID,
		ProjectRoot: projectRoot,
		ConversationRoot: filepath.Join(
			projectRoot,
			workspaceConversationsDir,
			conversationID,
		),
		LegacyRoot: legacyRoot,
	}, nil
}

func (paths agentWorkspacePaths) ensureConversationDir() error {
	if strings.TrimSpace(paths.ConversationRoot) == "" {
		return fmt.Errorf("会话工作区路径为空")
	}
	if err := os.MkdirAll(paths.ProjectRoot, 0o700); err != nil {
		return fmt.Errorf("创建项目工作区失败: %w", err)
	}
	if err := os.MkdirAll(paths.ConversationRoot, 0o700); err != nil {
		return fmt.Errorf("创建会话工作区失败: %w", err)
	}
	return nil
}

func (paths agentWorkspacePaths) conversationDirs() []string {
	result := []string{paths.ConversationRoot}
	if strings.TrimSpace(paths.LegacyRoot) != "" {
		result = append(result, paths.LegacyRoot)
	}
	return result
}

func validateWorkspacePathPart(value, label string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s不能为空，无法创建隔离工作区", label)
	}
	if filepath.Base(value) != value ||
		value == "." ||
		value == ".." ||
		strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("%s不合法，无法创建隔离工作区", label)
	}
	return nil
}
