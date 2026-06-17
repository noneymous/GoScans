/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package windows_systemcalls

import (
	"reflect"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

var (
	modShell32                            = windows.NewLazySystemDLL("shell32.dll")
	procSHGetPropertyStoreFromParsingName = modShell32.NewProc("SHGetPropertyStoreFromParsingName")
)

func SHGetPropertyStoreFromParsingName(pszPath *uint16, pbc *IBindCtx, flags uint32, riid *ole.GUID, obj interface{}) (err error) {
	objValue := reflect.ValueOf(obj).Elem()
	r0, _, _ := syscall.SyscallN(
		procSHGetPropertyStoreFromParsingName.Addr(),
		uintptr(unsafe.Pointer(pszPath)),
		uintptr(unsafe.Pointer(pbc)),
		uintptr(flags),
		uintptr(unsafe.Pointer(riid)),
		objValue.Addr().Pointer())

	if r0 != 0 {
		err = syscall.Errno(r0)
	}

	return
}

func psGetCount(ps *IPropertyStore, count *uint32) (err error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetCount,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(count)))
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psGetAt(ps *IPropertyStore, iProp uint32, pkey *PROPERTYKEY) (err error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetAt,
		uintptr(unsafe.Pointer(ps)),
		uintptr(iProp),
		uintptr(unsafe.Pointer(pkey)))
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psGetValue(ps *IPropertyStore, key *PROPERTYKEY, pv *PROPVARIANT) (err error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetValue,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(pv)))
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psSetValue() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}

func psCommit() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}
