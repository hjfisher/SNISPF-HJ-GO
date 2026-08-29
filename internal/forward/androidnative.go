//go:build android
// +build android

// androidnative.go - cgo JNI bridge for android.system.Os.setsocknetwork.
// This file is compiled when building for Android with CGO_ENABLED=1 and GOOS=android.
// It provides a function that calls android.system.Os.setsocknetwork(int fd) via JNI.
// The actual JNI implementation lives in the Android app's native library (androidnative.so)
// which is loaded by the Android app before starting the Go binary.

package forward

import (
	"errors"
)

// androidOsSetsocknetwork is set by the Android native library on JNI_OnLoad.
// It takes a file descriptor and calls android.system.Os.setsocknetwork(fd).
// Returns 0 on success, negative errno on failure.
var androidOsSetsocknetwork func(fd int64) int32

// androidNativeSetsocknetwork wraps android.system.Os.setsocknetwork.
// Returns nil on success, error otherwise.
func androidNativeSetsocknetwork(fd int64) error {
	if androidOsSetsocknetwork == nil {
		return errors.New("androidNativeSetsocknetwork: JNI not loaded (androidnative.so not loaded?)")
	}
	res := androidOsSetsocknetwork(fd)
	if res < 0 {
		return errors.New("android.system.Os.setsocknetwork failed")
	}
	return nil
}