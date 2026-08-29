//go:build android
// +build android
package internal/forward

import (
    "errors"
    "sync"
    "unsafe"
)

// #cgo LDFLAGS: -landroid -llog
// #cgo CFLAGS: -I${SRCDIR}/../androidnative/include
// #include <android/api-level.h>
// #include <android/native_window.h>
// #include <android/system/core/jni/android_system_os.h>
import (
    C "C"
)

// androidNativeSetsocknetwork wraps android.system.Os.setsocknetwork
// It sets the CAP_NET_RAW-like permissions for the given fd on Android.
func androidNativeSetsocknetwork(fd int64) error {
    if androidOsSetsocknetwork == nil {
        return errors.New("androidNativeSetsocknetwork: JNI not loaded")
    }
    return androidOsSetsocknetwork(C.long(fd))
}

//go:linkname androidOsSetsocknetwork github.com/hjfisher/SNISPF-HJ-Android/app/src/main/jniLibs/androidnative.SetSockNetwork
var androidOsSetsocknetwork func(fd C.long) error
