package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/execctx"
)

const (
	artifactOutputThreshold = 32 * 1024
	artifactPreviewBytes    = 2 * 1024
	artifactReadMaxBytes    = 24 * 1024
	artifactMaxFileBytes    = 8 * 1024 * 1024
	artifactMaxDirBytes     = 256 * 1024 * 1024
	artifactToolDir         = "tool_results"
	artifactLockStripes     = 64
)

var artifactLocks [artifactLockStripes]sync.Mutex

type artifactOutputTool struct {
	service *Service
	inner   tool.BaseTool
}

func wrapArtifactOutputTools(service *Service, items []tool.BaseTool) []tool.BaseTool {
	wrapped := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		wrapped = append(wrapped, &artifactOutputTool{service: service, inner: item})
	}
	return wrapped
}

func (t *artifactOutputTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.inner.Info(ctx)
}

// MCPServerName 转发 MCP 服务名，保证 artifact 包装后仍能被工具注册表识别。
func (t *artifactOutputTool) MCPServerName() string {
	if named, ok := t.inner.(serverNamedTool); ok {
		return named.MCPServerName()
	}
	return ""
}

func (t *artifactOutputTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	options ...tool.Option,
) (string, error) {
	invokable, ok := t.inner.(tool.InvokableTool)
	if !ok {
		return "", fmt.Errorf("工具 %s 不支持调用", t.toolName(ctx))
	}
	result, err := invokable.InvokableRun(ctx, argumentsInJSON, options...)
	if err != nil || len([]byte(result)) <= artifactOutputThreshold {
		return result, err
	}
	name := t.toolName(ctx)
	if shouldKeepToolOutputInline(name) {
		return result, nil
	}
	externalized, artifactErr := t.service.externalizeToolResult(ctx, name, result)
	if artifactErr != nil {
		return result + fmt.Sprintf("\n\n[artifact 外部化失败: %v]", artifactErr), nil
	}
	return externalized, nil
}

func (t *artifactOutputTool) toolName(ctx context.Context) string {
	if info, err := t.inner.Info(ctx); err == nil && info != nil {
		return strings.TrimSpace(info.Name)
	}
	return ""
}

func shouldKeepToolOutputInline(name string) bool {
	name = strings.TrimSpace(name)
	return strings.HasPrefix(name, "project_") ||
		strings.HasPrefix(name, "pent_agent_") ||
		name == readSkillToolName ||
		name == "read_artifact"
}

func newArtifactReaderTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: "read_artifact",
		desc: "读取当前会话 tool_results 目录中的工具原始输出 artifact。",
		params: map[string]*schema.ParameterInfo{
			"path": stringParam("artifact 绝对路径，必须位于当前会话 artifact 目录", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Path string `json:"path"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			path := strings.TrimSpace(request.Path)
			if path == "" {
				return "", fmt.Errorf("path 不能为空")
			}
			conversationID := sanitizeArtifactName(execctx.ConversationID(ctx))
			root := strings.TrimSpace(service.configSnapshot().Storage.ArtifactRoot)
			if conversationID == "" || root == "" {
				return "", fmt.Errorf("缺少会话或 artifact 根目录")
			}
			base := filepath.Join(root, "data", "conversation_artifacts", conversationID, artifactToolDir)
			absolute, err := filepath.Abs(path)
			if err != nil {
				return "", fmt.Errorf("artifact 路径不合法")
			}
			resolvedBase, err := filepath.EvalSymlinks(base)
			if err != nil {
				return "", fmt.Errorf("artifact 根目录不可用")
			}
			resolvedPath, err := filepath.EvalSymlinks(absolute)
			if err != nil {
				return "", fmt.Errorf("artifact 文件不存在")
			}
			rel, err := filepath.Rel(resolvedBase, resolvedPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return "", fmt.Errorf("artifact 路径越界")
			}
			rawBytes, err := os.ReadFile(resolvedPath)
			if err != nil {
				return "", fmt.Errorf("读取 artifact 失败: %w", err)
			}
			if len(rawBytes) > artifactReadMaxBytes {
				return string(rawBytes[:artifactReadMaxBytes]) + "\n\n[artifact 内容已截断]", nil
			}
			return string(rawBytes), nil
		},
	}
}

func (s *Service) externalizeToolResult(
	ctx context.Context,
	toolName string,
	result string,
) (string, error) {
	if s == nil {
		return "", fmt.Errorf("服务不可用")
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if conversationID == "" || root == "" {
		return "", fmt.Errorf("缺少会话或 artifact 根目录")
	}
	conversationDir := sanitizeArtifactName(conversationID)
	if conversationDir == "" {
		return "", fmt.Errorf("会话标识不合法")
	}
	dir := filepath.Join(root, "data", "conversation_artifacts", conversationDir, artifactToolDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("创建工具结果目录失败: %w", err)
	}
	raw := []byte(result)
	path, reason, err := writeArtifactUnderQuota(
		dir,
		toolName,
		result,
		artifactMaxFileBytes,
		artifactMaxDirBytes,
	)
	if err != nil {
		return "", err
	}
	if reason != "" {
		return artifactTooLargeResult(toolName, result, reason), nil
	}
	sum := sha256.Sum256(raw)
	head, tail := artifactPreview(result)
	var builder strings.Builder
	builder.WriteString("【工具输出已外部化】\n")
	builder.WriteString("工具: " + toolName + "\n")
	builder.WriteString(fmt.Sprintf("大小: %d bytes\n", len(raw)))
	builder.WriteString("SHA-256: " + hex.EncodeToString(sum[:]) + "\n")
	builder.WriteString("artifact: " + path + "\n")
	builder.WriteString("evidence_ref: file:" + path + "\n\n")
	builder.WriteString("[开头预览]\n")
	builder.WriteString(head)
	if tail != "" && tail != head {
		builder.WriteString("\n\n[结尾预览]\n")
		builder.WriteString(tail)
	}
	builder.WriteString("\n\n[完整原始输出已保存，需要细节时读取 artifact 文件。]")
	return builder.String(), nil
}

func writeArtifactUnderQuota(
	dir string,
	toolName string,
	result string,
	maxFileBytes int64,
	maxDirBytes int64,
) (string, string, error) {
	lock := artifactLockFor(dir)
	lock.Lock()
	defer lock.Unlock()

	raw := []byte(result)
	if int64(len(raw)) > maxFileBytes {
		return "", fmt.Sprintf("单文件超过 %d MiB", maxFileBytes/(1024*1024)), nil
	}
	currentBytes, err := artifactDirectoryBytes(dir)
	if err != nil {
		return "", "", fmt.Errorf("统计 artifact 容量失败: %w", err)
	}
	if currentBytes+int64(len(raw)) > maxDirBytes {
		return "", fmt.Sprintf("会话 artifact 超过 %d MiB 配额", maxDirBytes/(1024*1024)), nil
	}

	name := sanitizeArtifactName(toolName)
	if name == "" {
		name = "tool"
	}
	filename := fmt.Sprintf("%d-%s.txt", time.Now().UTC().UnixNano(), name)
	path := filepath.Join(dir, filename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("写入工具结果失败: %w", err)
	}
	if _, err := io.Copy(file, strings.NewReader(result)); err != nil {
		_ = file.Close()
		return "", "", fmt.Errorf("写入工具结果失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", "", fmt.Errorf("关闭工具结果文件失败: %w", err)
	}
	return path, "", nil
}

func artifactLockFor(dir string) *sync.Mutex {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(filepath.Clean(dir)))
	return &artifactLocks[hasher.Sum32()%artifactLockStripes]
}

func artifactTooLargeResult(toolName, result, reason string) string {
	head, tail := artifactPreview(result)
	var builder strings.Builder
	builder.WriteString("【工具输出未完整外部化】\n")
	builder.WriteString("工具: " + toolName + "\n")
	builder.WriteString("原因: " + reason + "\n\n")
	builder.WriteString("[开头预览]\n")
	builder.WriteString(head)
	if tail != "" && tail != head {
		builder.WriteString("\n\n[结尾预览]\n")
		builder.WriteString(tail)
	}
	builder.WriteString("\n\n[请缩小查询范围或分页后重新执行工具。]")
	return builder.String()
}

func artifactDirectoryBytes(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry == nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func artifactPreview(value string) (string, string) {
	raw := []byte(value)
	if len(raw) <= artifactPreviewBytes*2 {
		return value, ""
	}
	head := strings.ToValidUTF8(string(raw[:artifactPreviewBytes]), "")
	tailStart := len(raw) - artifactPreviewBytes
	if tailStart < 0 {
		tailStart = 0
	}
	tail := strings.ToValidUTF8(string(raw[tailStart:]), "")
	return head, tail
}

func sanitizeArtifactName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	name := strings.Trim(builder.String(), "-")
	runes := []rune(name)
	if len(runes) > 80 {
		name = string(runes[:80])
	}
	return name
}
