package handler

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"sophon/internal/database"
	"sophon/internal/middleware"
)

const (
	maxAttachmentBytes             = int64(2 * 1024 * 1024 * 1024)
	maxAttachmentMultipartOverhead = int64(4 * 1024 * 1024)
	maxAttachmentText              = 100 * 1024
	maxAttachmentReadBuffer        = 1024 * 1024
	maxPendingPerChat              = 20
	maxAttachmentNameLen           = 120
)

var (
	errAttachmentTooLarge = errors.New("attachment too large")
	errAttachmentEmpty    = errors.New("attachment empty")
)

var textAttachmentExtensions = map[string]bool{
	".txt": true, ".md": true, ".log": true, ".json": true, ".yaml": true,
	".yml": true, ".xml": true, ".csv": true, ".ini": true, ".conf": true,
	".sh": true, ".py": true, ".go": true, ".js": true, ".ts": true,
	".html": true, ".css": true, ".sql": true, ".toml": true,
}

type AttachmentHandler struct {
	db         *database.DB
	uploadsDir string
}

func NewAttachmentHandler(db *database.DB, uploadsDir string) *AttachmentHandler {
	return &AttachmentHandler{db: db, uploadsDir: filepath.Clean(uploadsDir)}
}

func (h *AttachmentHandler) Upload(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	conversation, ok := resolveOwnedConversation(c, h.db)
	if !ok {
		return
	}
	if strings.TrimSpace(conversation.ProjectID) == "" {
		badRequest(c, "project_required", "请先为对话绑定项目")
		return
	}
	if _, err := h.db.GetActiveProject(c.Request.Context(), conversation.ProjectID, user.ID); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "project_inactive",
				"message": "项目当前状态不允许上传附件",
			})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	ctx := c.Request.Context()
	pending, err := h.db.CountPendingAttachments(ctx, conversation.ID)
	if err != nil {
		internalError(c, "count_attachments_failed", "读取附件数量失败")
		return
	}
	if pending >= maxPendingPerChat {
		badRequest(c, "too_many_attachments", fmt.Sprintf("待发送附件最多 %d 个", maxPendingPerChat))
		return
	}

	bodyLimit := maxAttachmentBytes + maxAttachmentMultipartOverhead
	if c.Request.ContentLength > bodyLimit {
		attachmentTooLarge(c)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, bodyLimit)
	multipartReader, err := c.Request.MultipartReader()
	if err != nil {
		if isRequestBodyTooLarge(err) {
			attachmentTooLarge(c)
			return
		}
		badRequest(c, "invalid_file", "缺少上传文件或请求格式错误")
		return
	}

	id := randomID()
	name := ""
	var uploaded attachmentPartResult
	hasFile := false
	for {
		part, err := multipartReader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if isRequestBodyTooLarge(err) {
				attachmentTooLarge(c)
				return
			}
			badRequest(c, "invalid_file", "读取上传文件失败")
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if hasFile {
			_ = part.Close()
			badRequest(c, "invalid_file", "一次只能上传一个附件")
			return
		}
		hasFile = true
		name = safeAttachmentName(part.FileName())
		conversationDir := filepath.Join(h.uploadsDir, conversation.ID)
		if err := os.MkdirAll(conversationDir, 0o700); err != nil {
			_ = part.Close()
			internalError(c, "create_upload_dir_failed", "创建附件目录失败")
			return
		}
		uploaded, err = writeAttachmentPart(part, conversationDir, maxAttachmentBytes)
		_ = part.Close()
		if errors.Is(err, errAttachmentTooLarge) {
			attachmentTooLarge(c)
			return
		}
		if errors.Is(err, errAttachmentEmpty) {
			badRequest(c, "empty_file", "附件内容为空")
			return
		}
		if err != nil {
			if isRequestBodyTooLarge(err) {
				attachmentTooLarge(c)
				return
			}
			internalError(c, "write_file_failed", "保存附件失败")
			return
		}
	}
	if !hasFile {
		badRequest(c, "invalid_file", "缺少上传文件")
		return
	}

	mimeType := detectAttachmentMime(name, uploaded.sample)
	textContent := ""
	if isTextAttachment(name, mimeType) {
		if text := string(uploaded.textPrefix); utf8.ValidString(text) {
			textContent = text
		}
	}

	relativePath := filepath.Join(conversation.ID, id+"_"+name)
	absolutePath := filepath.Join(h.uploadsDir, relativePath)
	if !pathWithin(h.uploadsDir, absolutePath) {
		_ = os.Remove(uploaded.tempPath)
		internalError(c, "invalid_storage_path", "附件存储路径不合法")
		return
	}
	if err := os.Rename(uploaded.tempPath, absolutePath); err != nil {
		_ = os.Remove(uploaded.tempPath)
		internalError(c, "write_file_failed", "保存附件失败")
		return
	}

	item := database.Attachment{
		ID:             id,
		ConversationID: conversation.ID,
		FileName:       name,
		MimeType:       mimeType,
		SizeBytes:      uploaded.size,
		StoragePath:    relativePath,
		TextContent:    textContent,
		CreatedAt:      time.Now().UTC(),
	}
	if err := h.db.AddAttachment(ctx, item); err != nil {
		_ = os.Remove(absolutePath)
		internalError(c, "save_attachment_failed", "记录附件失败")
		return
	}
	c.JSON(http.StatusCreated, attachmentResponse(item))
}

type attachmentPartResult struct {
	tempPath   string
	size       int64
	sample     []byte
	textPrefix []byte
}

func writeAttachmentPart(
	part *multipart.Part,
	dir string,
	maxBytes int64,
) (attachmentPartResult, error) {
	result := attachmentPartResult{
		sample:     make([]byte, 0, 512),
		textPrefix: make([]byte, 0, maxAttachmentText),
	}
	file, err := os.CreateTemp(dir, ".upload-*.tmp")
	if err != nil {
		return result, fmt.Errorf("创建临时附件失败: %w", err)
	}
	result.tempPath = file.Name()
	keepTemp := false
	defer func() {
		_ = file.Close()
		if !keepTemp {
			_ = os.Remove(result.tempPath)
		}
	}()

	buffer := make([]byte, maxAttachmentReadBuffer)
	for {
		count, readErr := part.Read(buffer)
		if count > 0 {
			result.size += int64(count)
			if result.size > maxBytes {
				return result, errAttachmentTooLarge
			}
			if len(result.sample) < 512 {
				remaining := 512 - len(result.sample)
				if count < remaining {
					remaining = count
				}
				result.sample = append(result.sample, buffer[:remaining]...)
			}
			if len(result.textPrefix) < maxAttachmentText {
				remaining := maxAttachmentText - len(result.textPrefix)
				if count < remaining {
					remaining = count
				}
				result.textPrefix = append(result.textPrefix, buffer[:remaining]...)
			}
			if _, err := file.Write(buffer[:count]); err != nil {
				return result, fmt.Errorf("写入临时附件失败: %w", err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	if result.size == 0 {
		return result, errAttachmentEmpty
	}
	if err := file.Sync(); err != nil {
		return result, fmt.Errorf("同步临时附件失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return result, fmt.Errorf("关闭临时附件失败: %w", err)
	}
	keepTemp = true
	return result, nil
}

func attachmentTooLarge(c *gin.Context) {
	c.JSON(http.StatusRequestEntityTooLarge, gin.H{
		"code":    "file_too_large",
		"message": fmt.Sprintf("单个附件不能超过 %dGB", maxAttachmentBytes/(1024*1024*1024)),
	})
}

func isRequestBodyTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func (h *AttachmentHandler) List(c *gin.Context) {
	conversation, ok := resolveOwnedConversation(c, h.db)
	if !ok {
		return
	}
	items, err := h.db.ListAttachments(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "list_attachments_failed", "读取附件失败")
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, attachmentResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func (h *AttachmentHandler) Download(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetAttachment(c.Request.Context(), c.Param("id"))
	if err != nil {
		attachmentNotFound(c)
		return
	}
	if _, err := h.db.GetConversation(c.Request.Context(), item.ConversationID, user.ID); err != nil {
		attachmentNotFound(c)
		return
	}
	absolutePath := filepath.Join(h.uploadsDir, item.StoragePath)
	if !pathWithin(h.uploadsDir, absolutePath) {
		attachmentNotFound(c)
		return
	}
	c.FileAttachment(absolutePath, item.FileName)
}

func (h *AttachmentHandler) Delete(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetAttachment(c.Request.Context(), c.Param("id"))
	if err != nil {
		attachmentNotFound(c)
		return
	}
	if _, err := h.db.GetConversation(c.Request.Context(), item.ConversationID, user.ID); err != nil {
		attachmentNotFound(c)
		return
	}
	if item.MessageID != "" {
		badRequest(c, "attachment_in_use", "已发送的附件不能删除")
		return
	}
	if err := h.db.DeleteAttachment(c.Request.Context(), item.ID); err != nil {
		internalError(c, "delete_attachment_failed", "删除附件失败")
		return
	}
	absolutePath := filepath.Join(h.uploadsDir, item.StoragePath)
	if pathWithin(h.uploadsDir, absolutePath) {
		_ = os.Remove(absolutePath)
	}
	c.Status(http.StatusNoContent)
}

func attachmentResponse(item database.Attachment) gin.H {
	return gin.H{
		"id":             item.ID,
		"conversationId": item.ConversationID,
		"messageId":      item.MessageID,
		"fileName":       item.FileName,
		"mimeType":       item.MimeType,
		"sizeBytes":      item.SizeBytes,
		"createdAt":      item.CreatedAt,
	}
}

func attachmentNotFound(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{
		"code":    "attachment_not_found",
		"message": "附件不存在",
	})
}

// safeAttachmentName 去掉路径成分与控制字符，仅保留安全文件名。
func safeAttachmentName(raw string) string {
	name := filepath.Base(strings.TrimSpace(raw))
	var builder strings.Builder
	for _, r := range name {
		if r < 32 || r == 127 {
			continue
		}
		if strings.ContainsRune(`/\:*?"<>|`, r) {
			builder.WriteRune('_')
			continue
		}
		builder.WriteRune(r)
	}
	cleaned := strings.Trim(strings.TrimSpace(builder.String()), ".")
	if cleaned == "" {
		cleaned = "attachment"
	}
	runes := []rune(cleaned)
	if len(runes) > maxAttachmentNameLen {
		ext := []rune(filepath.Ext(cleaned))
		if len(ext) > 10 {
			ext = nil
		}
		keep := maxAttachmentNameLen - len(ext)
		if keep < 1 {
			keep = 1
		}
		cleaned = string(runes[:keep]) + string(ext)
	}
	return cleaned
}

func detectAttachmentMime(name string, data []byte) string {
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	detected := strings.TrimSpace(strings.SplitN(http.DetectContentType(sample), ";", 2)[0])
	if detected == "" || detected == "application/octet-stream" {
		if textAttachmentExtensions[strings.ToLower(filepath.Ext(name))] {
			return "text/plain"
		}
		return "application/octet-stream"
	}
	return detected
}

func isTextAttachment(name, mimeType string) bool {
	lower := strings.ToLower(strings.TrimSpace(mimeType))
	if strings.HasPrefix(lower, "text/") {
		return true
	}
	for _, marker := range []string{"json", "xml", "yaml", "javascript", "x-sh", "x-python"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return textAttachmentExtensions[strings.ToLower(filepath.Ext(name))]
}

// pathWithin 判断 target 是否位于 root 目录内（防止路径逃逸）。
func pathWithin(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
