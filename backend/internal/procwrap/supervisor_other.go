//go:build !linux

package procwrap

import (
	"fmt"
	"os"
	"os/exec"
)

func RunSupervisor(args []string) int {
	if len(args) < 2 || args[0] != "--" {
		fmt.Fprintf(os.Stderr, "用法: %s -- <command> [args...]\n", supervisorName)
		return 2
	}
	command := exec.Command(args[1], args[2:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
		return 125
	}
	return 0
}
