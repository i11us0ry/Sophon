package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sophon/internal/execctx"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	zhiziExecToolName     = "zhizi_exec"
	zhiziPythonToolName   = "zhizi_python"
	zhiziUploadToolName   = "zhizi_upload"
	zhiziDownloadToolName = "zhizi_download"
	zhiziStatusToolName   = "zhizi_status"

	maxZhiziCommandLength = 64 * 1024
	maxZhiziScriptLength  = 1024 * 1024
	maxZhiziLocalFile     = 32 * 1024 * 1024
)

func newZhiziTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{
		newZhiziExecTool(service),
		newZhiziPythonTool(service),
		newZhiziUploadTool(service),
		newZhiziDownloadTool(service),
		newZhiziStatusTool(service),
	}
}

func isZhiziToolName(name string) bool {
	switch strings.TrimSpace(name) {
	case zhiziExecToolName, zhiziPythonToolName, zhiziUploadToolName,
		zhiziDownloadToolName, zhiziStatusToolName:
		return true
	default:
		return false
	}
}

func (s *Service) hasActiveZhiziLease(ctx context.Context) bool {
	if s == nil || s.db == nil {
		return false
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return false
	}
	state, err := s.db.GetZhiziConversationState(ctx, conversationID, userID)
	return err == nil && state.Enabled && state.Lease != nil
}

func newZhiziExecTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: zhiziExecToolName,
		desc: "在当前对话绑定的智子分身 VPS 上执行 shell 命令。命令在独立会话工作区运行。",
		params: map[string]*schema.ParameterInfo{
			"command":         stringParam("要执行的 shell 命令", true),
			"timeout_seconds": integerParam("超时秒数，默认 120，最大 600"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Command        string  `json:"command"`
				TimeoutSeconds flexInt `json:"timeout_seconds"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			command := strings.TrimSpace(request.Command)
			if command == "" || len(command) > maxZhiziCommandLength {
				return "", fmt.Errorf("命令不能为空且不能超过 64KB")
			}
			conversationID, userID, err := zhiziExecutionContext(ctx, service)
			if err != nil {
				return "", err
			}
			args := map[string]interface{}{
				"command":         command,
				"timeout_seconds": int(request.TimeoutSeconds),
			}
			return service.runAuditedZhiziTool(ctx, zhiziExecToolName, args, func() (string, error) {
				result, err := service.zhizi.ExecConversation(
					ctx,
					conversationID,
					userID,
					command,
					time.Duration(request.TimeoutSeconds)*time.Second,
				)
				if err != nil {
					return "", err
				}
				return marshalToolPayload(result)
			})
		},
	}
}

func newZhiziPythonTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: zhiziPythonToolName,
		desc: "在当前对话绑定的智子分身 VPS 上执行 Python 3 脚本。脚本保存到当前会话远端工作区。",
		params: map[string]*schema.ParameterInfo{
			"script":          stringParam("Python 3 脚本正文", true),
			"timeout_seconds": integerParam("超时秒数，默认 120，最大 600"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Script         string  `json:"script"`
				TimeoutSeconds flexInt `json:"timeout_seconds"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			script := strings.TrimSpace(request.Script)
			if script == "" || len(script) > maxZhiziScriptLength {
				return "", fmt.Errorf("Python 脚本不能为空且不能超过 1MB")
			}
			conversationID, userID, err := zhiziExecutionContext(ctx, service)
			if err != nil {
				return "", err
			}
			args := map[string]interface{}{
				"script":          script,
				"timeout_seconds": int(request.TimeoutSeconds),
			}
			return service.runAuditedZhiziTool(ctx, zhiziPythonToolName, args, func() (string, error) {
				result, err := service.zhizi.RunPythonConversation(
					ctx,
					conversationID,
					userID,
					script,
					time.Duration(request.TimeoutSeconds)*time.Second,
				)
				if err != nil {
					return "", err
				}
				return marshalToolPayload(result)
			})
		},
	}
}

func newZhiziUploadTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: zhiziUploadToolName,
		desc: "把当前对话工作区或上传目录中的文件上传到智子分身远端工作区。",
		params: map[string]*schema.ParameterInfo{
			"local_path":  stringParam("当前会话本地文件绝对路径", true),
			"remote_path": stringParam("远端工作区内的相对路径", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				LocalPath  string `json:"local_path"`
				RemotePath string `json:"remote_path"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			localPath, err := service.validateZhiziLocalInput(ctx, request.LocalPath)
			if err != nil {
				return "", err
			}
			conversationID, userID, err := zhiziExecutionContext(ctx, service)
			if err != nil {
				return "", err
			}
			args := map[string]interface{}{
				"local_path":  localPath,
				"remote_path": request.RemotePath,
			}
			return service.runAuditedZhiziTool(ctx, zhiziUploadToolName, args, func() (string, error) {
				info, err := os.Stat(localPath)
				if err != nil || !info.Mode().IsRegular() {
					return "", fmt.Errorf("本地文件不存在或不是普通文件")
				}
				if info.Size() > maxZhiziLocalFile {
					return "", fmt.Errorf("上传文件不能超过 32MB")
				}
				content, err := os.ReadFile(localPath)
				if err != nil {
					return "", fmt.Errorf("读取本地文件失败: %w", err)
				}
				if err := service.zhizi.UploadConversation(
					ctx,
					conversationID,
					userID,
					request.RemotePath,
					content,
				); err != nil {
					return "", err
				}
				return marshalToolPayload(map[string]interface{}{
					"status":     "uploaded",
					"localPath":  localPath,
					"remotePath": request.RemotePath,
					"sizeBytes":  len(content),
				})
			})
		},
	}
}

func newZhiziDownloadTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: zhiziDownloadToolName,
		desc: "从智子分身远端工作区下载文件到当前会话 artifact 目录。",
		params: map[string]*schema.ParameterInfo{
			"remote_path": stringParam("远端工作区内的相对路径", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				RemotePath string `json:"remote_path"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			conversationID, userID, err := zhiziExecutionContext(ctx, service)
			if err != nil {
				return "", err
			}
			args := map[string]interface{}{
				"remote_path": request.RemotePath,
			}
			return service.runAuditedZhiziTool(ctx, zhiziDownloadToolName, args, func() (string, error) {
				content, err := service.zhizi.DownloadConversation(
					ctx,
					conversationID,
					userID,
					request.RemotePath,
				)
				if err != nil {
					return "", err
				}
				root := strings.TrimSpace(service.configSnapshot().Storage.ArtifactRoot)
				if root == "" {
					return "", fmt.Errorf("存储根目录未配置")
				}
				dir := filepath.Join(root, "data", "conversation_artifacts", conversationID, "zhizi_downloads")
				if err := os.MkdirAll(dir, 0o750); err != nil {
					return "", fmt.Errorf("创建下载目录失败: %w", err)
				}
				name := filepath.Base(strings.ReplaceAll(request.RemotePath, "\\", "/"))
				if name == "" || name == "." || name == ".." {
					name = "download.bin"
				}
				target := filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), name))
				if err := os.WriteFile(target, content, 0o600); err != nil {
					return "", fmt.Errorf("保存远端文件失败: %w", err)
				}
				return marshalToolPayload(map[string]interface{}{
					"status":     "downloaded",
					"path":       target,
					"sizeBytes":  len(content),
					"remotePath": request.RemotePath,
				})
			})
		},
	}
}

func newZhiziStatusTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name:   zhiziStatusToolName,
		desc:   "查看当前对话的智子分身绑定、节点和剩余容量。",
		params: map[string]*schema.ParameterInfo{},
		run: func(ctx context.Context, _ string) (string, error) {
			conversationID, userID, err := zhiziExecutionContext(ctx, service)
			if err != nil {
				return "", err
			}
			return service.runAuditedZhiziTool(ctx, zhiziStatusToolName, map[string]interface{}{}, func() (string, error) {
				state, err := service.db.GetZhiziConversationState(ctx, conversationID, userID)
				if err != nil {
					return "", err
				}
				availability, err := service.db.ZhiziAvailability(ctx)
				if err != nil {
					return "", err
				}
				return marshalToolPayload(map[string]interface{}{
					"state":        state,
					"availability": availability,
				})
			})
		},
	}
}

func zhiziExecutionContext(ctx context.Context, service *Service) (string, string, error) {
	if service == nil || service.db == nil || service.zhizi == nil {
		return "", "", fmt.Errorf("智子分身服务不可用")
	}
	if _, _, _, err := service.currentProject(ctx); err != nil {
		return "", "", err
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return "", "", fmt.Errorf("缺少会话上下文")
	}
	return conversationID, userID, nil
}

func (s *Service) validateZhiziLocalInput(ctx context.Context, raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", fmt.Errorf("本地路径不能为空")
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if root == "" || conversationID == "" {
		return "", fmt.Errorf("本地存储或会话上下文不可用")
	}
	_, userID, projectID, err := s.currentProject(ctx)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absolute); resolveErr == nil {
		absolute = resolved
	}
	bases := []string{
		filepath.Join(root, "chat_uploads", conversationID),
		filepath.Join(root, "tmp", "workspace", conversationID),
		filepath.Join(root, "data", "conversation_artifacts", conversationID),
	}
	conversations, err := s.db.ListProjectConversations(ctx, projectID, userID)
	if err != nil {
		return "", err
	}
	for _, conversation := range conversations {
		bases = append(bases,
			filepath.Join(root, "chat_uploads", conversation.ID),
			filepath.Join(root, "tmp", "workspace", conversation.ID),
			filepath.Join(root, "data", "conversation_artifacts", conversation.ID),
		)
	}
	for _, base := range bases {
		resolvedBase := base
		if resolved, resolveErr := filepath.EvalSymlinks(base); resolveErr == nil {
			resolvedBase = resolved
		}
		rel, relErr := filepath.Rel(resolvedBase, absolute)
		if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("本地路径不在当前会话允许范围内")
}

func (s *Service) authorizeZhiziTool(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
) error {
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return fmt.Errorf("缺少会话上下文")
	}
	var progress ProgressFunc
	if fn, ok := execctx.Progress(ctx); ok {
		progress = func(event Event) error {
			return fn(event.Type, event.Message, event.Data)
		}
	}
	return s.toolInterceptor(conversationID, userID, progress)(
		ctx,
		"sophon-zhizi",
		toolName,
		args,
	)
}

func (s *Service) runAuditedZhiziTool(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
	run func() (string, error),
) (string, error) {
	if err := s.authorizeZhiziTool(ctx, toolName, args); err != nil {
		return "", err
	}
	executionID := s.db.StartToolExecution(
		ctx,
		strings.TrimSpace(execctx.ConversationID(ctx)),
		strings.TrimSpace(execctx.UserID(ctx)),
		toolName,
		args,
	)
	result, err := run()
	s.db.FinishToolExecution(ctx, executionID, result, err)
	return result, err
}

func marshalToolPayload(value interface{}) (string, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
