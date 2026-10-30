//go:build !windows
// +build !windows

package pool

import "os"

func atomicRename(oldPath, newPath string) error {
	_ = os.Remove(newPath)
	return os.Rename(oldPath, newPath)
}
