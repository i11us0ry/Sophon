package handler

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	storagepkg "sophon/internal/storage"

	"github.com/gin-gonic/gin"
)

const (
	workspaceDefaultListLimit = 500
	workspaceMaxListLimit     = 2000
	workspaceMaxBatchDelete   = 200
	workspaceMaxEditBytes     = 1 << 20
	workspaceEditableCategory = "workspace"
)

var (
	errWorkspaceNotRegular = errors.New("workspace path is not a regular file")
	errWorkspaceTooLarge   = errors.New("workspace file is too large")
	errWorkspaceNotText    = errors.New("workspace file is not utf-8 text")
)

type workspaceTextFile struct {
	Content    string
	Size       int64
	MTime      int64
	Version    string
	LineEnding string
}

type WorkspaceHandler struct {
	storage *storagepkg.Service
}

func NewWorkspaceHandler(service *storagepkg.Service) *WorkspaceHandler {
	return &WorkspaceHandler{storage: service}
}

func (h *WorkspaceHandler) Categories(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	items := make([]gin.H, 0)
	configured := h.storage.Config().Categories
	for _, category := range storagepkg.Categories {
		if category.Kind != storagepkg.CategoryKindDirectory {
			continue
		}
		if _, ok := configured[category.Name]; !ok {
			continue
		}
		items = append(items, gin.H{
			"name":  category.Name,
			"label": category.Label,
			"path":  category.Path,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *WorkspaceHandler) List(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	root, _, abs, err := h.resolve(c.Query("category"), c.Query("path"))
	if err != nil {
		badRequest(c, "invalid_workspace_path", err.Error())
		return
	}
	if info, statErr := os.Stat(abs); statErr != nil {
		if os.IsNotExist(statErr) {
			c.JSON(http.StatusOK, gin.H{
				"path":    "",
				"entries": []gin.H{},
				"total":   0,
				"hasMore": false,
			})
			return
		}
		internalError(c, "workspace_list_failed", "读取工作空间目录失败")
		return
	} else if !info.IsDir() {
		badRequest(c, "not_a_directory", "目标不是目录")
		return
	}
	dirEntries, err := os.ReadDir(abs)
	if err != nil {
		internalError(c, "workspace_list_failed", "读取工作空间目录失败")
		return
	}
	type workspaceEntry struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		Dir   bool   `json:"dir"`
		Size  int64  `json:"size"`
		MTime int64  `json:"mtime"`
	}
	entries := make([]workspaceEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		full := filepath.Join(abs, entry.Name())
		rel, relErr := filepath.Rel(root, full)
		if relErr != nil {
			continue
		}
		entries = append(entries, workspaceEntry{
			Name:  entry.Name(),
			Path:  filepath.ToSlash(rel),
			Dir:   info.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	total := len(entries)
	limit := clampQueryInt(c.Query("limit"), workspaceDefaultListLimit, 1, workspaceMaxListLimit)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	currentPath, _ := filepath.Rel(root, abs)
	if currentPath == "." {
		currentPath = ""
	}
	c.JSON(http.StatusOK, gin.H{
		"path":       filepath.ToSlash(currentPath),
		"entries":    entries[offset:end],
		"total":      total,
		"hasMore":    end < total,
		"nextOffset": end,
	})
}

func (h *WorkspaceHandler) Content(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	_, _, abs, err := h.resolve(c.Query("category"), c.Query("path"))
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"code": "workspace_file_not_found", "message": "文件不存在"})
			return
		}
		badRequest(c, "invalid_workspace_path", err.Error())
		return
	}
	file, err := readWorkspaceTextFile(abs)
	if err != nil {
		switch {
		case errors.Is(err, errWorkspaceNotRegular):
			badRequest(c, "not_a_file", "目标不是普通文件")
		case errors.Is(err, errWorkspaceTooLarge):
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"code":    "workspace_file_too_large",
				"message": fmt.Sprintf("在线查看上限为 %d KiB", workspaceMaxEditBytes/1024),
			})
		case errors.Is(err, errWorkspaceNotText):
			c.JSON(http.StatusUnsupportedMediaType, gin.H{
				"code":    "workspace_binary_file",
				"message": "该文件不是 UTF-8 文本，请下载后查看",
			})
		case os.IsNotExist(err):
			c.JSON(http.StatusNotFound, gin.H{"code": "workspace_file_not_found", "message": "文件不存在"})
		default:
			internalError(c, "workspace_read_failed", "读取文件失败")
		}
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"path":       filepath.ToSlash(strings.TrimSpace(c.Query("path"))),
		"content":    file.Content,
		"size":       file.Size,
		"mtime":      file.MTime,
		"version":    file.Version,
		"lineEnding": file.LineEnding,
		"editable":   strings.TrimSpace(c.Query("category")) == workspaceEditableCategory,
	})
}

func (h *WorkspaceHandler) SaveContent(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	if strings.TrimSpace(c.Query("category")) != workspaceEditableCategory {
		c.JSON(http.StatusForbidden, gin.H{
			"code":    "workspace_category_read_only",
			"message": "仅 Agent 工作区支持在线编辑",
		})
		return
	}
	expectedVersion := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Workspace-Version")))
	if len(expectedVersion) != sha256.Size*2 {
		badRequest(c, "invalid_workspace_version", "缺少有效的文件版本")
		return
	}
	lineEnding := strings.ToLower(strings.TrimSpace(c.GetHeader("X-Workspace-Line-Ending")))
	if lineEnding == "" {
		lineEnding = "lf"
	}
	if lineEnding != "lf" && lineEnding != "crlf" {
		badRequest(c, "invalid_line_ending", "换行格式必须是 lf 或 crlf")
		return
	}
	if c.Request.ContentLength > workspaceMaxEditBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"code":    "workspace_content_too_large",
			"message": fmt.Sprintf("在线编辑上限为 %d KiB", workspaceMaxEditBytes/1024),
		})
		return
	}
	payload, err := io.ReadAll(io.LimitReader(c.Request.Body, workspaceMaxEditBytes+1))
	if err != nil {
		badRequest(c, "invalid_workspace_content", "读取编辑内容失败")
		return
	}
	if len(payload) > workspaceMaxEditBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"code":    "workspace_content_too_large",
			"message": fmt.Sprintf("在线编辑上限为 %d KiB", workspaceMaxEditBytes/1024),
		})
		return
	}
	content := normalizeWorkspaceLineEnding(string(payload), lineEnding)
	contentBytes := []byte(content)
	if len(contentBytes) > workspaceMaxEditBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{
			"code":    "workspace_content_too_large",
			"message": fmt.Sprintf("在线编辑上限为 %d KiB", workspaceMaxEditBytes/1024),
		})
		return
	}
	if !validWorkspaceText(contentBytes) {
		badRequest(c, "invalid_workspace_content", "编辑内容必须是 UTF-8 文本")
		return
	}

	_, _, abs, err := h.resolve(c.Query("category"), c.Query("path"))
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"code": "workspace_file_not_found", "message": "文件不存在"})
			return
		}
		badRequest(c, "invalid_workspace_path", err.Error())
		return
	}
	current, err := readWorkspaceTextFile(abs)
	if err != nil {
		if errors.Is(err, errWorkspaceTooLarge) || errors.Is(err, errWorkspaceNotText) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "workspace_file_changed",
				"message": "文件已变化，请重新加载后再编辑",
			})
			return
		}
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"code": "workspace_file_not_found", "message": "文件不存在"})
			return
		}
		badRequest(c, "not_a_file", "目标不是可编辑文件")
		return
	}
	if current.Version != expectedVersion {
		c.JSON(http.StatusConflict, gin.H{
			"code":           "workspace_file_conflict",
			"message":        "文件已被其他任务修改，请重新加载",
			"currentVersion": current.Version,
			"currentMTime":   current.MTime,
		})
		return
	}

	updated, err := writeWorkspaceTextFile(abs, contentBytes)
	if err != nil {
		internalError(c, "workspace_write_failed", "保存文件失败")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"path":       filepath.ToSlash(strings.TrimSpace(c.Query("path"))),
		"size":       updated.Size,
		"mtime":      updated.MTime,
		"version":    updated.Version,
		"lineEnding": lineEnding,
	})
}

func (h *WorkspaceHandler) Download(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	_, _, abs, err := h.resolve(c.Query("category"), c.Query("path"))
	if err != nil {
		badRequest(c, "invalid_workspace_path", err.Error())
		return
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"code": "workspace_file_not_found", "message": "文件不存在"})
		return
	}
	name := workspaceFileName(filepath.Base(abs))
	c.Header(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, name, url.PathEscape(name)),
	)
	c.File(abs)
}

func (h *WorkspaceHandler) Delete(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	root, lexical, abs, err := h.resolve(c.Query("category"), c.Query("path"))
	if err != nil {
		badRequest(c, "invalid_workspace_path", err.Error())
		return
	}
	if abs == root {
		badRequest(c, "workspace_root_delete", "不能删除工作空间根目录")
		return
	}
	if info, lstatErr := os.Lstat(lexical); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		badRequest(c, "workspace_symlink_delete", "不允许删除符号链接")
		return
	}
	if _, statErr := os.Stat(abs); statErr != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": "workspace_path_not_found", "message": "路径不存在"})
		return
	}
	if err := os.RemoveAll(abs); err != nil {
		internalError(c, "workspace_delete_failed", "删除失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *WorkspaceHandler) BatchDelete(c *gin.Context) {
	if h.storage == nil {
		internalError(c, "workspace_unavailable", "工作空间不可用")
		return
	}
	var request struct {
		Category string   `json:"category"`
		Paths    []string `json:"paths"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "批量删除参数格式错误")
		return
	}
	if len(request.Paths) == 0 || len(request.Paths) > workspaceMaxBatchDelete {
		badRequest(c, "invalid_paths", fmt.Sprintf("单次最多删除 %d 项", workspaceMaxBatchDelete))
		return
	}
	deleted := 0
	failed := make([]gin.H, 0)
	for _, path := range request.Paths {
		root, lexical, abs, err := h.resolve(request.Category, path)
		if err != nil || abs == root {
			failed = append(failed, gin.H{"path": path, "reason": "路径不合法"})
			continue
		}
		if info, lstatErr := os.Lstat(lexical); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			failed = append(failed, gin.H{"path": path, "reason": "不允许删除符号链接"})
			continue
		}
		if err := os.RemoveAll(abs); err != nil {
			failed = append(failed, gin.H{"path": path, "reason": err.Error()})
			continue
		}
		deleted++
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted, "failed": failed})
}

// resolve 将类别相对路径解析为安全的绝对路径：
// - 仅允许 storage 中配置的目录类别
// - 拒绝越界、根目录逃逸和外链符号链接
func (h *WorkspaceHandler) resolve(category, rel string) (string, string, string, error) {
	if h.storage == nil {
		return "", "", "", fmt.Errorf("工作空间不可用")
	}
	category = strings.TrimSpace(category)
	item, ok := storagepkg.CategoryByName(category)
	if !ok || item.Kind != storagepkg.CategoryKindDirectory {
		return "", "", "", fmt.Errorf("工作空间类别不合法")
	}
	root, err := h.storage.CategoryDir(item.Name)
	if err != nil {
		return "", "", "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", "", err
	}
	realRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", "", fmt.Errorf("工作空间目录不存在")
	}
	rel = strings.TrimSpace(rel)
	if strings.ContainsRune(rel, 0) {
		return "", "", "", fmt.Errorf("路径不合法")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", "", "", fmt.Errorf("不允许使用绝对路径")
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return "", "", "", fmt.Errorf("路径不允许包含 ..")
		}
	}
	clean := filepath.Clean("/" + strings.TrimLeft(rel, `/\`))
	lexical := filepath.Join(realRoot, clean)
	if lexical != realRoot && !strings.HasPrefix(lexical, realRoot+string(os.PathSeparator)) {
		return "", "", "", fmt.Errorf("路径超出工作空间")
	}
	realTarget, err := filepath.EvalSymlinks(lexical)
	if err != nil {
		return "", "", "", err
	}
	if realTarget != realRoot && !strings.HasPrefix(realTarget, realRoot+string(os.PathSeparator)) {
		return "", "", "", fmt.Errorf("路径超出工作空间")
	}
	return realRoot, lexical, realTarget, nil
}

func workspaceFileName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, `"`, "_")
	name = strings.ReplaceAll(name, "\n", "_")
	name = strings.ReplaceAll(name, "\r", "_")
	if name == "" {
		return "download"
	}
	return name
}

func readWorkspaceTextFile(path string) (workspaceTextFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return workspaceTextFile{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return workspaceTextFile{}, err
	}
	if !info.Mode().IsRegular() {
		return workspaceTextFile{}, errWorkspaceNotRegular
	}
	if info.Size() > workspaceMaxEditBytes {
		return workspaceTextFile{}, errWorkspaceTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, workspaceMaxEditBytes+1))
	if err != nil {
		return workspaceTextFile{}, err
	}
	if len(data) > workspaceMaxEditBytes {
		return workspaceTextFile{}, errWorkspaceTooLarge
	}
	if !validWorkspaceText(data) {
		return workspaceTextFile{}, errWorkspaceNotText
	}
	return workspaceTextFile{
		Content:    string(data),
		Size:       int64(len(data)),
		MTime:      info.ModTime().UnixMilli(),
		Version:    workspaceContentVersion(data),
		LineEnding: detectWorkspaceLineEnding(data),
	}, nil
}

func writeWorkspaceTextFile(path string, data []byte) (workspaceTextFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return workspaceTextFile{}, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".sophon-edit-*")
	if err != nil {
		return workspaceTextFile{}, err
	}
	tempPath := temp.Name()
	renamed := false
	defer func() {
		_ = temp.Close()
		if !renamed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return workspaceTextFile{}, err
	}
	if _, err := temp.Write(data); err != nil {
		return workspaceTextFile{}, err
	}
	if err := temp.Sync(); err != nil {
		return workspaceTextFile{}, err
	}
	if err := temp.Close(); err != nil {
		return workspaceTextFile{}, err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return workspaceTextFile{}, err
	}
	renamed = true
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	updated, err := os.Stat(path)
	if err != nil {
		return workspaceTextFile{}, err
	}
	return workspaceTextFile{
		Size:       int64(len(data)),
		MTime:      updated.ModTime().UnixMilli(),
		Version:    workspaceContentVersion(data),
		LineEnding: detectWorkspaceLineEnding(data),
	}, nil
}

func validWorkspaceText(data []byte) bool {
	return utf8.Valid(data) && bytes.IndexByte(data, 0) < 0
}

func workspaceContentVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func detectWorkspaceLineEnding(data []byte) string {
	crlf := bytes.Count(data, []byte("\r\n"))
	lf := bytes.Count(data, []byte("\n"))
	if crlf > 0 && lf == crlf {
		return "crlf"
	}
	return "lf"
}

func normalizeWorkspaceLineEnding(content, lineEnding string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	if lineEnding == "crlf" {
		return strings.ReplaceAll(content, "\n", "\r\n")
	}
	return content
}
