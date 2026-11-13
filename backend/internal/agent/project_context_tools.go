package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	searchProjectHistoryToolName   = "search_project_history"
	discoverProjectSourcesToolName = "discover_project_sources"
)

type projectFileEntry struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Source   bool   `json:"source"`
}

func newProjectContextTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{
		newSearchProjectHistoryTool(service),
		newDiscoverProjectSourcesTool(service),
	}
}

func newSearchProjectHistoryTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: searchProjectHistoryToolName,
		desc: "搜索当前用户当前项目下所有对话的历史消息。query 可为空以直接返回最近消息；支持指定 limit 和 offset。",
		params: map[string]*schema.ParameterInfo{
			"query":  stringParam("搜索关键词；留空时返回最近消息"),
			"limit":  integerParam("返回条数，默认 20，最大 50"),
			"offset": integerParam("分页偏移，默认 0"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Query  string  `json:"query"`
				Limit  flexInt `json:"limit"`
				Offset flexInt `json:"offset"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := service.currentProject(ctx)
			if err != nil {
				return "", err
			}
			items, total, err := service.db.SearchProjectHistory(
				ctx,
				projectID,
				userID,
				request.Query,
				int(request.Limit),
				int(request.Offset),
			)
			if err != nil {
				return "", fmt.Errorf("搜索项目聊天记录失败: %w", err)
			}
			payload := map[string]interface{}{
				"total": total,
				"items": items,
			}
			rawJSON, _ := json.MarshalIndent(payload, "", "  ")
			return string(rawJSON), nil
		},
	}
}

func newDiscoverProjectSourcesTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: discoverProjectSourcesToolName,
		desc: "列出当前用户当前项目所有上传目录、工作区和会话产物中的文件。query 可按路径过滤，支持 limit 和 offset；不读取文件正文。",
		params: map[string]*schema.ParameterInfo{
			"query":  stringParam("按路径或文件名过滤，可留空"),
			"limit":  integerParam("返回条数，默认 200，最大 1000"),
			"offset": integerParam("分页偏移，默认 0"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Query  string  `json:"query"`
				Limit  flexInt `json:"limit"`
				Offset flexInt `json:"offset"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			entries, total, truncated, err := service.discoverProjectFiles(
				ctx,
				request.Query,
				int(request.Limit),
				int(request.Offset),
			)
			if err != nil {
				return "", err
			}
			payload := map[string]interface{}{
				"total":     total,
				"truncated": truncated,
				"items":     entries,
			}
			rawJSON, _ := json.MarshalIndent(payload, "", "  ")
			return string(rawJSON), nil
		},
	}
}

func (s *Service) discoverProjectFiles(
	ctx context.Context,
	query string,
	limit int,
	offset int,
) ([]projectFileEntry, int, bool, error) {
	if s == nil || s.db == nil {
		return nil, 0, false, fmt.Errorf("项目文件服务不可用")
	}
	_, userID, projectID, err := s.currentProject(ctx)
	if err != nil {
		return nil, 0, false, err
	}
	root := strings.TrimSpace(s.configSnapshot().Storage.ArtifactRoot)
	if root == "" {
		return nil, 0, false, fmt.Errorf("存储根目录未配置")
	}
	conversations, err := s.db.ListProjectConversations(ctx, projectID, userID)
	if err != nil {
		return nil, 0, false, err
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	query = strings.ToLower(strings.TrimSpace(query))
	const maxScannedEntries = 5000
	entries := make([]projectFileEntry, 0, min(maxScannedEntries, limit+offset))
	truncated := false
	seen := map[string]bool{}
	for _, conversation := range conversations {
		for _, base := range []struct {
			kind string
			path string
		}{
			{"upload", filepath.Join(root, "chat_uploads", conversation.ID)},
			{"workspace", filepath.Join(root, "tmp", "workspace", conversation.ID)},
			{"artifact", filepath.Join(root, "data", "conversation_artifacts", conversation.ID)},
		} {
			if info, statErr := os.Stat(base.path); statErr != nil || !info.IsDir() {
				continue
			}
			walkErr := filepath.WalkDir(base.path, func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil || entry == nil {
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					if entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if entry.IsDir() {
					return nil
				}
				if query != "" && !strings.Contains(strings.ToLower(path), query) {
					return nil
				}
				if seen[path] {
					return nil
				}
				seen[path] = true
				if len(entries) >= maxScannedEntries {
					truncated = true
					return filepath.SkipAll
				}
				info, infoErr := entry.Info()
				if infoErr != nil {
					return nil
				}
				entries = append(entries, projectFileEntry{
					Path:     path,
					Kind:     base.kind,
					Size:     info.Size(),
					Modified: info.ModTime().UTC().Format(time.RFC3339),
					Source:   isProjectSourceFile(path),
				})
				return nil
			})
			if walkErr != nil && walkErr != filepath.SkipAll {
				return nil, 0, false, walkErr
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return entries[i].Source
		}
		return entries[i].Path < entries[j].Path
	})
	total := len(entries)
	if offset >= total {
		return []projectFileEntry{}, total, truncated, nil
	}
	end := min(total, offset+limit)
	return entries[offset:end], total, truncated, nil
}

func isProjectSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".go", ".js", ".ts", ".tsx", ".jsx", ".java", ".py", ".rb", ".php",
		".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".swift", ".kt", ".kts",
		".scala", ".sh", ".sql", ".yaml", ".yml", ".json", ".xml", ".html", ".htm",
		".aspx", ".ashx", ".asmx", ".config", ".sln", ".csproj", ".dll", ".jar", ".war":
		return true
	default:
		return false
	}
}
