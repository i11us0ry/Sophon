//go:build !windows

package app

import "syscall"

// RestrictProcessUmask 让进程后续新建的文件默认仅属主可读写（目录 0700、文件 0600）。
func RestrictProcessUmask() {
	syscall.Umask(0o077)
}
