package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	attachmentContextMaxFiles = 5
	attachmentContextPerFile  = 1200
	attachmentContextMaxRunes = 6000
)

// attachmentDigest 把最近上传的附件压缩成上下文片段：文本附件给出正文摘要，
// 其他附件给出磁盘路径供工具读取。
func (s *Service) attachmentDigest(ctx context.Context, conversationID string) string {
	if s.db == nil || strings.TrimSpace(conversationID) == "" {
		return ""
	}
	items, err := s.db.ListRecentAttachments(ctx, conversationID, attachmentContextMaxFiles)
	if err != nil || len(items) == 0 {
		return ""
	}
	uploadsRoot := filepath.Join(s.configSnapshot().Storage.ArtifactRoot, "chat_uploads")
	var builder strings.Builder
	used := 0
	for _, item := range items {
		line := fmt.Sprintf(
			"- %s（%s，%s）",
			item.FileName,
			attachmentMimeLabel(item.MimeType),
			attachmentHumanSize(item.SizeBytes),
		)
		if text := strings.TrimSpace(item.TextContent); text != "" {
			line += "：\n  " + strings.ReplaceAll(
				truncateHead(text, attachmentContextPerFile),
				"\n",
				"\n  ",
			)
		} else {
			line += "\n  非文本文件，可用工具读取：" + filepath.Join(uploadsRoot, item.StoragePath)
		}
		size := len([]rune(line))
		if used > 0 && used+size+1 > attachmentContextMaxRunes {
			break
		}
		if used > 0 {
			builder.WriteString("\n")
			used++
		}
		builder.WriteString(line)
		used += size
	}
	return strings.TrimSpace(builder.String())
}

func attachmentMimeLabel(mimeType string) string {
	if strings.TrimSpace(mimeType) == "" {
		return "未知类型"
	}
	return mimeType
}

func attachmentHumanSize(size int64) string {
	switch {
	case size >= 1024*1024:
		return fmt.Sprintf("%.1fMB", float64(size)/(1024*1024))
	case size >= 1024:
		return fmt.Sprintf("%.1fKB", float64(size)/1024)
	default:
		return fmt.Sprintf("%dB", size)
	}
}
