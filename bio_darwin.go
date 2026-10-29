//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include <stdlib.h>
#include "bio_darwin.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const keychainService = "gpass"
const errSecItemNotFound = -25300

func biometricAvailable() bool { return C.bio_available() == 1 }

func biometricAuth(reason string) error {
	cr := C.CString(reason)
	defer C.free(unsafe.Pointer(cr))
	switch C.bio_authenticate(cr) {
	case 0:
		return nil
	case 1:
		return errBiometricCancelled
	}
	return fmt.Errorf("touch id authentication failed")
}

func keychainSet(account string, secret []byte) error {
	cs, ca := C.CString(keychainService), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var p *C.uchar
	if len(secret) > 0 {
		p = (*C.uchar)(unsafe.Pointer(&secret[0]))
	}
	if st := C.kc_set(cs, ca, p, C.int(len(secret))); st != 0 {
		return fmt.Errorf("keychain write failed (OSStatus %d)", int(st))
	}
	return nil
}

func keychainExists(account string) bool {
	cs, ca := C.CString(keychainService), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	return C.kc_exists(cs, ca) == 0
}

func keychainGet(account string) ([]byte, error) {
	cs, ca := C.CString(keychainService), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var out *C.uchar
	var n C.int
	st := C.kc_get(cs, ca, &out, &n)
	if st != 0 {
		return nil, fmt.Errorf("keychain read failed (OSStatus %d)", int(st))
	}
	defer C.kc_free(out, n)
	return C.GoBytes(unsafe.Pointer(out), n), nil
}

func keychainDelete(account string) error {
	cs, ca := C.CString(keychainService), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	if st := C.kc_delete(cs, ca); st != 0 && int(st) != errSecItemNotFound {
		return fmt.Errorf("keychain delete failed (OSStatus %d)", int(st))
	}
	return nil
}
