//go:build windows

package app

// RestrictProcessUmask 在 Windows 上没有对应语义，保留空实现以保持跨平台编译。
func RestrictProcessUmask() {}
