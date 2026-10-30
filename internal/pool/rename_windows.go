//go:build windows
// +build windows

package pool

import (
	"golang.org/x/sys/windows"
	"syscall"
)

func atomicRename(oldPath, newPath string) error {
	from, err := syscall.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
}
