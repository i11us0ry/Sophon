package procwrap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandContextUsesConfiguredSupervisor(t *testing.T) {
	supervisor := filepath.Join(t.TempDir(), supervisorName)
	if err := os.WriteFile(supervisor, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvSupervisorPath, supervisor)

	cmd := CommandContext(context.Background(), "/bin/echo", "hello")
	if cmd.Path != supervisor {
		t.Fatalf("应使用 supervisor，实际 %s", cmd.Path)
	}
	got := strings.Join(cmd.Args, "\x00")
	if !strings.Contains(got, "--\x00/bin/echo\x00hello") {
		t.Fatalf("supervisor 参数不正确: %q", cmd.Args)
	}
	if cmd.Cancel == nil || cmd.WaitDelay <= 0 {
		t.Fatal("supervisor 命令缺少取消或等待保护")
	}
}

func TestBinaryPathRejectsMissingConfiguredSupervisor(t *testing.T) {
	t.Setenv(EnvSupervisorPath, filepath.Join(t.TempDir(), "missing"))
	if _, err := BinaryPath(); err == nil {
		t.Fatal("配置了不存在的 supervisor 时应返回错误")
	}
}
