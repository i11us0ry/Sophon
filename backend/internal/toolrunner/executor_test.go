package toolrunner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func intPointer(value int) *int {
	return &value
}

func TestResolveTimeoutPrefersGlobalCeiling(t *testing.T) {
	executor := &Executor{Timeout: 900 * time.Second}
	if got := executor.resolveTimeout(Tool{Name: "nmap", TimeoutSeconds: 900}); got != 900*time.Second {
		t.Fatalf("工具超时应等于全局上限，实际 %s", got)
	}
	if got := executor.resolveTimeout(Tool{Name: "fast", TimeoutSeconds: 60}); got != 60*time.Second {
		t.Fatalf("工具级超时应收紧，实际 %s", got)
	}
	if got := executor.resolveTimeout(Tool{Name: "inherit"}); got != 900*time.Second {
		t.Fatalf("未声明超时应继承全局上限，实际 %s", got)
	}
	// 工具声明的超时不允许突破全局上限。
	if got := executor.resolveTimeout(Tool{Name: "greedy", TimeoutSeconds: 3600}); got != 900*time.Second {
		t.Fatalf("工具超时不得突破全局上限，实际 %s", got)
	}
	if got := (&Executor{}).resolveTimeout(Tool{}); got != defaultRunTimeout {
		t.Fatalf("未配置全局超时应回落到默认值，实际 %s", got)
	}
}

func TestBuildArgsFormats(t *testing.T) {
	item := Tool{
		Name:    "demo",
		Command: "demo",
		Parameters: []Parameter{
			{Name: "mode", Type: "string", Position: intPointer(0), Default: "dir"},
			{Name: "target", Type: "string", Required: true, Flag: "-t", Format: "flag"},
			{Name: "ports", Type: "string", Flag: "-p"},
			{Name: "level", Type: "int", Flag: "--level", Format: "combined"},
			{Name: "timing", Type: "string", Format: "template", Template: "-T{value}"},
			{Name: "verbose", Type: "bool", Flag: "-v"},
			{Name: "quiet", Type: "bool", Flag: "-q"},
			{Name: "url", Type: "string", Position: intPointer(1), Required: true},
			{Name: "additional_args", Type: "string"},
		},
	}
	args := map[string]any{
		"target":          "example.com",
		"ports":           "80, 443",
		"level":           float64(3),
		"timing":          "4",
		"verbose":         true,
		"quiet":           false,
		"url":             "http://example.com",
		"additional_args": `--foo "a b"`,
	}

	got, err := BuildArgs(item, args)
	if err != nil {
		t.Fatalf("拼装失败: %v", err)
	}
	want := []string{
		"dir",
		"-t", "example.com",
		"-p", "80,443",
		"--level=3",
		"-T4",
		"-v",
		"http://example.com",
		"--foo", "a b",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("参数不正确\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildArgsObjectParamWithoutDoubleEncoding(t *testing.T) {
	item := Tool{
		Name: "http-framework-test",
		Parameters: []Parameter{
			{Name: "url", Type: "string", Required: true, Flag: "--url"},
			{Name: "headers", Type: "object", Flag: "--headers"},
		},
	}
	jsonText := `{"Content-Type": "application/x-www-form-urlencoded"}`
	args, err := BuildArgs(item, map[string]any{
		"url":     "http://example.com",
		"headers": jsonText,
	})
	if err != nil {
		t.Fatalf("构建参数失败: %v", err)
	}
	want := []string{"--url", "http://example.com", "--headers", jsonText}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("JSON 字符串形式的 object 参数不应二次编码\nwant=%q\ngot =%q", want, args)
	}

	args, err = BuildArgs(item, map[string]any{
		"url":     "http://example.com",
		"headers": map[string]any{"X-Test": "1"},
	})
	if err != nil {
		t.Fatalf("构建参数失败: %v", err)
	}
	if args[3] != `{"X-Test":"1"}` {
		t.Fatalf("map 形式应序列化为 JSON，实际 %q", args[3])
	}

	args, err = BuildArgs(item, map[string]any{
		"url":     "http://example.com",
		"headers": "X-Test: 1",
	})
	if err != nil {
		t.Fatalf("构建参数失败: %v", err)
	}
	if args[3] != "X-Test: 1" {
		t.Fatalf("非 JSON 字符串应原样透传，实际 %q", args[3])
	}
}

func TestBuildArgsRejectsMissingRequired(t *testing.T) {
	item := Tool{
		Name:       "demo",
		Command:    "demo",
		Parameters: []Parameter{{Name: "target", Type: "string", Required: true, Flag: "-t"}},
	}
	if _, err := BuildArgs(item, map[string]any{}); err == nil {
		t.Fatalf("缺少必需参数应报错")
	}
}

func TestExecutorRunsCommand(t *testing.T) {
	executor := &Executor{Timeout: 5 * time.Second}
	result, err := executor.Run(context.Background(), Tool{
		Name:    "echo-demo",
		Command: "echo",
		Args:    []string{"hello"},
	}, nil)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(result.Output, "hello") {
		t.Fatalf("输出不正确: %q", result.Output)
	}
}

func TestExecutorTimeoutKillsChildProcessGroup(t *testing.T) {
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "orphan-child.txt")
	executor := &Executor{Timeout: 150 * time.Millisecond, WorkspaceRoot: workspace}
	command := fmt.Sprintf(`sleep 1; printf leaked > %q`, marker)
	_, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":           command,
		"_sophon_workspace": workspace,
	})
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("命令应因超时失败: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("超时后子进程仍在运行并写入文件: %v", statErr)
	}
}

func TestExecutorRejectsDetachedBackground(t *testing.T) {
	workspace := t.TempDir()
	executor := &Executor{Timeout: 5 * time.Second, WorkspaceRoot: workspace}
	_, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":           "nohup sleep 10 >/dev/null 2>&1 &",
		"_sophon_workspace": workspace,
	})
	if err == nil || !strings.Contains(err.Error(), "job(action=start)") {
		t.Fatalf("后台命令应被拒绝并提示受控 Job: %v", err)
	}
}

func TestExecutorRejectsPythonDetachedSession(t *testing.T) {
	executor := &Executor{Timeout: 5 * time.Second}
	_, err := executor.Run(context.Background(), Tool{
		Name:    "execute-python-script",
		Command: "true",
		Parameters: []Parameter{
			{Name: "script", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"script": "import os\nos.setsid()",
	})
	if err == nil || !strings.Contains(err.Error(), "进程组") {
		t.Fatalf("应拒绝 Python setsid 脱离进程组: %v", err)
	}
}

func TestExecutorProcessCountBudgetKillsGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process count budget requires Linux process group semantics")
	}
	workspace := t.TempDir()
	executor := &Executor{Timeout: 5 * time.Second, WorkspaceRoot: workspace}
	started := time.Now()
	_, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":               "sleep 2",
		"_sophon_workspace":     workspace,
		"_sophon_max_processes": 1,
	})
	if err == nil || !strings.Contains(err.Error(), "进程数") {
		t.Fatalf("进程数超限应终止进程组: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("进程数超限后未及时终止: %s", elapsed)
	}
}

func TestExecutorKillsBackgroundChildAfterMainProcessExit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("background child cleanup requires Linux process group semantics")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 不可用")
	}
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "background-child.txt")
	script := fmt.Sprintf(
		"import os,time\npid=os.fork()\nif pid==0:\n os.close(1)\n os.close(2)\n time.sleep(1)\n open(%q,'w').write('leaked')\n os._exit(0)\n",
		marker,
	)
	executor := &Executor{Timeout: 5 * time.Second, WorkspaceRoot: workspace}
	_, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":           "python3 -c " + shellQuote(script),
		"_sophon_workspace": workspace,
	})
	if err == nil || !strings.Contains(err.Error(), "后台子进程") {
		t.Fatalf("主进程退出后应清理后台子进程: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("后台子进程未被终止: %v", statErr)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func TestRewriteTemporaryPaths(t *testing.T) {
	workspace := "/opt/sophon/tmp/workspace/conversation-1"
	command := `curl https://example.com/tmp/source -o /tmp/result.txt; head /tmp/result.txt`
	got := rewriteTemporaryPaths(command, workspace)
	want := `curl https://example.com/tmp/source -o /opt/sophon/tmp/workspace/conversation-1/result.txt; head /opt/sophon/tmp/workspace/conversation-1/result.txt`
	if got != want {
		t.Fatalf("临时路径重写异常\n got: %s\nwant: %s", got, want)
	}
	if got := rewriteTemporaryPaths("printf /tmpfoo", workspace); got != "printf /tmpfoo" {
		t.Fatalf("相似前缀不应被重写: %q", got)
	}
}

func TestExecutorUsesSessionWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "conversation-1")
	tmpFile := filepath.Join(
		string(filepath.Separator),
		"tmp",
		fmt.Sprintf("sophon-workspace-%d.txt", time.Now().UnixNano()),
	)
	t.Cleanup(func() { _ = os.Remove(tmpFile) })
	command := fmt.Sprintf(
		`printf 'workspace=%s tmp=%%s home=%%s\n' "$TMPDIR" "$HOME"; printf ok > %s`,
		workspace,
		tmpFile,
	)
	executor := &Executor{
		Timeout:       5 * time.Second,
		WorkspaceRoot: root,
	}
	result, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":           command,
		"_sophon_workspace": workspace,
	})
	if err != nil {
		t.Fatalf("会话工作区执行失败: %v", err)
	}
	if !strings.Contains(result.Output, "workspace="+workspace) ||
		!strings.Contains(result.Output, "tmp="+workspace) ||
		!strings.Contains(result.Output, "home="+workspace) {
		t.Fatalf("命令未在会话工作区执行: %q", result.Output)
	}
	content, err := os.ReadFile(filepath.Join(workspace, filepath.Base(tmpFile)))
	if err != nil || string(content) != "ok" {
		t.Fatalf("产物未写入会话工作区: content=%q err=%v", content, err)
	}
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Fatalf("全局 /tmp 不应产生文件: %v", err)
	}
}

func TestExecutorExposesConversationWorkspace(t *testing.T) {
	root := t.TempDir()
	conversation := filepath.Join(root, "conversation-1")
	worker := filepath.Join(conversation, "subagents", "worker-1")
	executor := &Executor{Timeout: 5 * time.Second, WorkspaceRoot: root}
	result, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":                        `printf 'pwd=%s\nworkspace=%s\nconversation=%s\n' "$PWD" "$SOPHON_WORKSPACE" "$SOPHON_CONVERSATION_WORKSPACE"`,
		"_sophon_workspace":              worker,
		"_sophon_conversation_workspace": conversation,
	})
	if err != nil {
		t.Fatalf("共享工作区环境变量执行失败: %v", err)
	}
	realWorker, err := filepath.EvalSymlinks(worker)
	if err != nil {
		t.Fatalf("解析 Worker 工作区失败: %v", err)
	}
	if !strings.Contains(result.Output, "pwd="+realWorker) ||
		!strings.Contains(result.Output, "workspace="+worker) ||
		!strings.Contains(result.Output, "conversation="+conversation) {
		t.Fatalf("Worker 工作区环境不正确: %q", result.Output)
	}
}

func TestExecutorRejectsWorkspaceOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	executor := &Executor{Timeout: 5 * time.Second, WorkspaceRoot: root}
	_, err := executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":           "pwd",
		"_sophon_workspace": outside,
	})
	if err == nil || !strings.Contains(err.Error(), "超出") {
		t.Fatalf("越界工作区应被拒绝: %v", err)
	}
	_, err = executor.Run(context.Background(), Tool{
		Name:    "exec",
		Command: "sh",
		Args:    []string{"-c"},
		Parameters: []Parameter{
			{Name: "command", Position: intPointer(0), Required: true},
		},
	}, map[string]any{
		"command":                        "pwd",
		"_sophon_workspace":              filepath.Join(root, "worker"),
		"_sophon_conversation_workspace": outside,
	})
	if err == nil || !strings.Contains(err.Error(), "超出") {
		t.Fatalf("越界共享工作区应被拒绝: %v", err)
	}
}

func TestExecutorReportsCommandNotFound(t *testing.T) {
	executor := &Executor{Timeout: 5 * time.Second}
	_, err := executor.Run(context.Background(), Tool{
		Name:    "missing-demo",
		Command: "definitely-not-a-real-command-xyz",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "失败") {
		t.Fatalf("缺失命令应返回错误: %v", err)
	}
}

func TestBoundedOutputBufferCapsMemory(t *testing.T) {
	buffer := newBoundedOutputBuffer(32)
	payload := []byte(strings.Repeat("A", 1024))
	written, err := buffer.Write(payload)
	if err != nil || written != len(payload) {
		t.Fatalf("写入有界缓冲失败: written=%d err=%v", written, err)
	}
	if buffer.data.Len() != 32 || buffer.total != 1024 {
		t.Fatalf("有界缓冲统计异常: len=%d total=%d", buffer.data.Len(), buffer.total)
	}
	output := buffer.String()
	if !strings.Contains(output, "输出超过") || len(output) > 128 {
		t.Fatalf("截断提示异常: %q", output)
	}
}
