package procwrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	EnvSupervisorPath = "SOPHON_PROCESS_SUPERVISOR"
	supervisorName    = "sophon-process-supervisor"
)

// Require 确保生产进程能找到子进程回收器，避免静默退回不会回收孤儿子进程的执行方式。
func Require() error {
	_, err := BinaryPath()
	return err
}

func BinaryPath() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(EnvSupervisorPath)); configured != "" {
		if executableFile(configured) {
			return configured, nil
		}
		return "", fmt.Errorf("%s 指向的进程回收器不可执行: %s", EnvSupervisorPath, configured)
	}
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), supervisorName)
		if executableFile(candidate) {
			return candidate, nil
		}
	}
	candidate := filepath.Join("/opt/sophon/backend", supervisorName)
	if executableFile(candidate) {
		return candidate, nil
	}
	if path, err := exec.LookPath(supervisorName); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("未找到 %s", supervisorName)
}

// CommandContext 在生产环境优先通过 subreaper 包装器启动命令；测试环境缺少包装器时保留直连回退。
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	supervisor, err := BinaryPath()
	if err != nil {
		return exec.CommandContext(ctx, name, args...)
	}
	wrappedArgs := make([]string, 0, len(args)+2)
	wrappedArgs = append(wrappedArgs, "--", name)
	wrappedArgs = append(wrappedArgs, args...)
	cmd := exec.CommandContext(ctx, supervisor, wrappedArgs...)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 4 * time.Second
	return cmd
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0
}
