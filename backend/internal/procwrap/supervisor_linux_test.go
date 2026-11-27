//go:build linux

package procwrap

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSupervisorProcessHelper(t *testing.T) {
	if os.Getenv("SOPHON_PROCWRAP_HELPER") != "1" {
		return
	}
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("缺少 supervisor 参数分隔符")
	}
	os.Exit(RunSupervisor(os.Args[index:]))
}

func TestRunSupervisorReapsBackgroundChild(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := `sleep 30 & echo $! > "$1"; exit 0`
	cmd := exec.Command(
		os.Args[0],
		"-test.run=TestSupervisorProcessHelper",
		"--",
		"/bin/sh",
		"-c",
		script,
		"sh",
		pidFile,
	)
	cmd.Env = append(os.Environ(), "SOPHON_PROCWRAP_HELPER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("supervisor 执行失败: %v: %s", err, output)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	childPID, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || childPID <= 0 {
		t.Fatalf("子进程 PID 无效: %q", raw)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("后台子进程 %d 未被回收", childPID)
}

func TestRunSupervisorPreservesExitCode(t *testing.T) {
	cmd := exec.Command(
		os.Args[0],
		"-test.run=TestSupervisorProcessHelper",
		"--",
		"/bin/sh",
		"-c",
		"exit 7",
	)
	cmd.Env = append(os.Environ(), "SOPHON_PROCWRAP_HELPER=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("退出码未透传，err=%v", err)
	}
}
