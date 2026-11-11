package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/execctx"
)

type artifactTestTool struct {
	name   string
	result string
}

func (t *artifactTestTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name, Desc: "artifact test"}, nil
}

func (t *artifactTestTool) InvokableRun(
	_ context.Context,
	_ string,
	_ ...tool.Option,
) (string, error) {
	return t.result, nil
}

func TestArtifactOutputToolExternalizesLargeResult(t *testing.T) {
	root := t.TempDir()
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{ArtifactRoot: root},
	}}
	result := strings.Repeat("安全测试输出\n", 5000)
	wrapped := wrapArtifactOutputTools(service, []tool.BaseTool{
		&artifactTestTool{name: "large_scan", result: result},
	})[0]
	invokable := wrapped.(tool.InvokableTool)
	ctx := execctx.WithConversationID(context.Background(), "conv-artifact")
	out, err := invokable.InvokableRun(ctx, "{}")
	if err != nil {
		t.Fatalf("执行包装工具失败: %v", err)
	}
	if !strings.Contains(out, "工具输出已外部化") || !strings.Contains(out, "evidence_ref: file:") {
		t.Fatalf("大结果应返回 artifact 引用: %q", out)
	}
	path := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "artifact: ") {
			path = strings.TrimPrefix(line, "artifact: ")
			break
		}
	}
	if path == "" || !strings.HasPrefix(path, root) {
		t.Fatalf("artifact 路径异常: %q", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 artifact 失败: %v", err)
	}
	if string(raw) != result {
		t.Fatalf("artifact 内容不完整")
	}
	if filepath.Base(filepath.Dir(path)) != artifactToolDir {
		t.Fatalf("artifact 目录异常: %s", path)
	}
	reader := newArtifactReaderTool(service).(tool.InvokableTool)
	content, err := reader.InvokableRun(ctx, `{"path":`+strconv.Quote(path)+`}`)
	if err != nil || !strings.HasPrefix(content, "安全测试输出") || !strings.Contains(content, "artifact 内容已截断") {
		t.Fatalf("read_artifact 读取失败: %v", err)
	}
	if _, err := reader.InvokableRun(ctx, `{"path":"/etc/passwd"}`); err == nil {
		t.Fatalf("read_artifact 应拒绝越界路径")
	}
}

func TestArtifactOutputToolKeepsSmallResultInline(t *testing.T) {
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{ArtifactRoot: t.TempDir()},
	}}
	wrapped := wrapArtifactOutputTools(service, []tool.BaseTool{
		&artifactTestTool{name: "small_scan", result: "small result"},
	})[0]
	out, err := wrapped.(tool.InvokableTool).InvokableRun(
		execctx.WithConversationID(context.Background(), "conv-small"),
		"{}",
	)
	if err != nil || out != "small result" {
		t.Fatalf("小结果不应外部化: %q err=%v", out, err)
	}
}

func TestArtifactOutputToolRejectsOversizedResult(t *testing.T) {
	root := t.TempDir()
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{ArtifactRoot: root},
	}}
	result := strings.Repeat("A", artifactMaxFileBytes+1)
	wrapped := wrapArtifactOutputTools(service, []tool.BaseTool{
		&artifactTestTool{name: "oversized_scan", result: result},
	})[0]
	out, err := wrapped.(tool.InvokableTool).InvokableRun(
		execctx.WithConversationID(context.Background(), "conv-oversized"),
		"{}",
	)
	if err != nil {
		t.Fatalf("超大结果处理失败: %v", err)
	}
	if !strings.Contains(out, "工具输出未完整外部化") ||
		!strings.Contains(out, "单文件超过") {
		t.Fatalf("超大结果应返回容量提示: %q", out)
	}
	entries, err := os.ReadDir(filepath.Join(
		root,
		"data",
		"conversation_artifacts",
		"conv-oversized",
		artifactToolDir,
	))
	if err == nil && len(entries) > 0 {
		t.Fatalf("超大结果不应创建 artifact 文件: %v", entries)
	}
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("检查 artifact 目录失败: %v", err)
	}
}

func TestWriteArtifactUnderQuotaSerializesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("创建测试目录失败: %v", err)
	}
	results := []string{
		strings.Repeat("A", 600),
		strings.Repeat("B", 600),
	}
	var wait sync.WaitGroup
	reasons := make(chan string, len(results))
	errorsCh := make(chan error, len(results))
	for _, result := range results {
		wait.Add(1)
		go func(value string) {
			defer wait.Done()
			_, reason, err := writeArtifactUnderQuota(
				dir,
				"concurrent",
				value,
				1000,
				1000,
			)
			if err != nil {
				errorsCh <- err
				return
			}
			if reason != "" {
				reasons <- reason
			}
		}(result)
	}
	wait.Wait()
	close(errorsCh)
	close(reasons)
	for err := range errorsCh {
		t.Fatalf("并发写入失败: %v", err)
	}
	if len(reasons) != 1 {
		t.Fatalf("应有一个写入被配额拒绝，实际 %d", len(reasons))
	}
	total, err := artifactDirectoryBytes(dir)
	if err != nil {
		t.Fatalf("统计 artifact 容量失败: %v", err)
	}
	if total > 1000 {
		t.Fatalf("并发写入突破配额: %d", total)
	}
}
