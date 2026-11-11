package handler

import (
	"bytes"
	"errors"
	"mime/multipart"
	"os"
	"strings"
	"testing"
)

func TestSafeAttachmentName(t *testing.T) {
	if got := safeAttachmentName("../../etc/passwd"); got != "passwd" {
		t.Fatalf("路径穿越文件名清洗错误: %q", got)
	}
	if got := safeAttachmentName(""); got != "attachment" {
		t.Fatalf("空文件名应回退为 attachment: %q", got)
	}
	if got := safeAttachmentName("..."); got != "attachment" {
		t.Fatalf("纯点文件名应回退为 attachment: %q", got)
	}
	if got := safeAttachmentName("a\x00b\nc.txt"); strings.ContainsAny(got, "\x00\n") {
		t.Fatalf("控制字符未清理: %q", got)
	}
	got := safeAttachmentName(`..\..\evil.txt`)
	if strings.ContainsAny(got, `/\`) || strings.HasPrefix(got, ".") {
		t.Fatalf("反斜杠路径未清理: %q", got)
	}
	long := safeAttachmentName(strings.Repeat("名", 200) + ".txt")
	if len([]rune(long)) > maxAttachmentNameLen {
		t.Fatalf("文件名超长未截断: %d", len([]rune(long)))
	}
	if !strings.HasSuffix(long, ".txt") {
		t.Fatalf("截断应保留扩展名: %q", long)
	}
}

func TestTextAttachmentDetection(t *testing.T) {
	if !isTextAttachment("notes.txt", "application/octet-stream") {
		t.Fatalf(".txt 应识别为文本附件")
	}
	if !isTextAttachment("data", "application/json") {
		t.Fatalf("application/json 应识别为文本附件")
	}
	if isTextAttachment("scan.bin", "application/octet-stream") {
		t.Fatalf("二进制附件不应识别为文本")
	}
	if got := detectAttachmentMime("report.md", []byte("# title\n\ncontent")); !strings.HasPrefix(got, "text/") {
		t.Fatalf("markdown 应识别为文本类型: %q", got)
	}
	if got := detectAttachmentMime("blob.bin", []byte{0x00, 0x01, 0x02, 0x03}); got != "application/octet-stream" {
		t.Fatalf("二进制类型识别错误: %q", got)
	}
}

func TestPathWithin(t *testing.T) {
	if !pathWithin("/tmp/root", "/tmp/root/a/b.txt") {
		t.Fatalf("子路径应在根目录内")
	}
	if pathWithin("/tmp/root", "/tmp/root/../escape.txt") {
		t.Fatalf("路径逃逸应被拒绝")
	}
	if pathWithin("/tmp/root", "/tmp/other/file.txt") {
		t.Fatalf("外部路径应被拒绝")
	}
}

func TestWriteAttachmentPartStreamsToTempFile(t *testing.T) {
	dir := t.TempDir()
	part := multipartPart(t, "scan.log", bytes.Repeat([]byte("A"), 2*1024*1024))
	result, err := writeAttachmentPart(part, dir, 3*1024*1024)
	if err != nil {
		t.Fatalf("流式写入附件失败: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(result.tempPath) })
	if result.size != 2*1024*1024 || len(result.sample) != 512 {
		t.Fatalf("附件统计错误: size=%d sample=%d", result.size, len(result.sample))
	}
	info, err := os.Stat(result.tempPath)
	if err != nil || info.Size() != result.size {
		t.Fatalf("临时文件大小错误: info=%+v err=%v", info, err)
	}
	if !pathWithin(dir, result.tempPath) {
		t.Fatalf("临时文件路径越界: %s", result.tempPath)
	}
}

func TestAttachmentLimitIsTwoGB(t *testing.T) {
	if maxAttachmentBytes != int64(2*1024*1024*1024) {
		t.Fatalf("附件上限应为 2GB，实际 %d", maxAttachmentBytes)
	}
	if maxAttachmentMultipartOverhead < 1*1024*1024 {
		t.Fatalf("multipart 预留空间过小: %d", maxAttachmentMultipartOverhead)
	}
}

func TestWriteAttachmentPartRejectsOversizedFileAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	part := multipartPart(t, "large.bin", bytes.Repeat([]byte{0x7f}, 2048))
	_, err := writeAttachmentPart(part, dir, 1024)
	if !errors.Is(err, errAttachmentTooLarge) {
		t.Fatalf("超大附件应返回错误，实际 %v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("读取目录失败: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("超大附件不应残留临时文件: %v", entries)
	}
}

func multipartPart(t *testing.T, name string, data []byte) *multipart.Part {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatalf("创建 multipart 文件失败: %v", err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatalf("写入 multipart 文件失败: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 multipart writer 失败: %v", err)
	}
	reader := multipart.NewReader(&body, writer.Boundary())
	part, err := reader.NextPart()
	if err != nil {
		t.Fatalf("读取 multipart part 失败: %v", err)
	}
	return part
}

func TestWriteAttachmentPartRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	part := multipartPart(t, "empty.txt", nil)
	_, err := writeAttachmentPart(part, dir, 1024)
	if !errors.Is(err, errAttachmentEmpty) {
		t.Fatalf("空附件应返回错误，实际 %v", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("读取目录失败: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("空附件不应残留临时文件: %v", entries)
	}
}
