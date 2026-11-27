//go:build linux

package procwrap

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	descendantTerminateGrace = 300 * time.Millisecond
	descendantKillGrace      = 3 * time.Second
)

// RunSupervisor 作为单条命令的 subreaper，负责转发信号并回收整棵子进程树。
func RunSupervisor(args []string) int {
	command, commandArgs, err := supervisorCommand(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "设置子进程回收器失败: %v\n", err)
		return 125
	}
	if err := syscall.Setpgid(0, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		fmt.Fprintf(os.Stderr, "创建进程组失败: %v\n", err)
		return 125
	}
	path, err := exec.LookPath(command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "找不到命令 %s: %v\n", command, err)
		return 127
	}
	process, err := os.StartProcess(path, commandArgs, &os.ProcAttr{
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动命令 %s 失败: %v\n", command, err)
		return 126
	}
	code := superviseProcess(process)
	_ = process.Release()
	return code
}

func supervisorCommand(args []string) (string, []string, error) {
	if len(args) < 2 || args[0] != "--" {
		return "", nil, fmt.Errorf("用法: %s -- <command> [args...]", supervisorName)
	}
	command := strings.TrimSpace(args[1])
	if command == "" {
		return "", nil, fmt.Errorf("目标命令不能为空")
	}
	return command, append([]string(nil), args[1:]...), nil
}

func superviseProcess(process *os.Process) int {
	mainPID := process.Pid
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

	var mainStatus syscall.WaitStatus
	mainExited := false
	var cleanupAt time.Time
	var killAt time.Time

	for {
		noChildren := reapChildren(mainPID, &mainStatus, &mainExited)
		now := time.Now()
		if noChildren && mainExited {
			return supervisorExitCode(mainStatus)
		}
		if noChildren && !mainExited {
			fmt.Fprintln(os.Stderr, "目标命令未返回退出状态")
			return 125
		}
		if mainExited && cleanupAt.IsZero() {
			cleanupAt = now.Add(descendantTerminateGrace)
			signalDescendants(syscall.SIGTERM)
		}
		if !cleanupAt.IsZero() && !now.Before(cleanupAt) && killAt.IsZero() {
			signalDescendants(syscall.SIGKILL)
			killAt = now.Add(descendantKillGrace)
		}
		if !killAt.IsZero() && !now.Before(killAt) {
			fmt.Fprintln(os.Stderr, "回收命令子进程树超时")
			return 125
		}

		select {
		case received := <-signals:
			if sig, ok := received.(syscall.Signal); ok {
				signalDescendants(sig)
			}
			if cleanupAt.IsZero() {
				cleanupAt = now.Add(time.Second)
			}
		case <-ticker.C:
		}
	}
}

func reapChildren(
	mainPID int,
	mainStatus *syscall.WaitStatus,
	mainExited *bool,
) bool {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		switch {
		case pid > 0:
			if pid == mainPID {
				*mainStatus = status
				*mainExited = true
			}
		case err == nil:
			return false
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.ECHILD):
			return true
		default:
			return false
		}
	}
}

func signalDescendants(sig syscall.Signal) {
	for _, pid := range descendantPIDs(os.Getpid(), make(map[int]bool)) {
		_ = syscall.Kill(pid, sig)
	}
}

func descendantPIDs(pid int, seen map[int]bool) []int {
	if seen[pid] {
		return nil
	}
	seen[pid] = true
	children := childPIDs(pid)
	result := make([]int, 0, len(children))
	for _, child := range children {
		childIDs := descendantPIDs(child, seen)
		if len(childIDs) > 0 {
			result = append(result, childIDs...)
		}
		result = append(result, child)
	}
	return result
}

func childPIDs(pid int) []int {
	path := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(raw))
	result := make([]int, 0, len(fields))
	for _, field := range fields {
		child, err := strconv.Atoi(field)
		if err == nil && child > 0 {
			result = append(result, child)
		}
	}
	return result
}

func supervisorExitCode(status syscall.WaitStatus) int {
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}
