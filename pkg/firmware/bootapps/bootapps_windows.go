package bootapps

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	FirmwareTypeUnknown = uint32(0)
	FirmwareTypeBios    = iota
	FirmwareTypeUefi
	FirmwareTypeMax
)

type SYSTEM_BOOT_ENVIRONMENT_INFORMATION struct {
	BootIdentifier [16]byte
	FirmwareType   uint32
	BootFlags      uint64
}

func getEfiSystemPartPath() (string, error) {
	// verify that this is a UEFI boot
	var bootInfo SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	err := windows.NtQuerySystemInformation(windows.SystemBootEnvironmentInformation, unsafe.Pointer(&bootInfo), uint32(unsafe.Sizeof(bootInfo)), nil)
	if err != nil {
		return "", err
	}

	if bootInfo.FirmwareType != FirmwareTypeUefi {
		return "", errors.New("no UEFI boot")
	}

	// the following code gets the system boot partition name and is here as a fallback in case the shortcut doesn't work on some systems
	// get the efi system partition name as windows.NTUnicodeString
	// 520 is pulled from tracing how mountvol.exe
	/*buf := make([]byte, 520)
	bufSz := uint32(len(buf))
	err = windows.NtQuerySystemInformation(windows.SystemSystemPartitionInformation, unsafe.Pointer(&buf[0]), bufSz, &bufSz)
	if err != nil {
		return "", err
	}

	if bufSz > uint32(len(buf)) {
		return "", errors.New("buffer too small")
	}

	// cast the raw buffer and do some sanity checks; the structure contains lengths and a pointer that
	// should point to more data that mus be wholly inside our initial buffer
	ntStr := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if ptrSz, dataPtr := unsafe.Sizeof(ntStr.Buffer), uintptr(unsafe.Pointer(ntStr.Buffer)); uintptr(ntStr.MaximumLength) != (uintptr(len(buf))-unsafe.Offsetof(ntStr.Buffer)-ptrSz) || dataPtr < (uintptr(unsafe.Pointer(&ntStr.Buffer))+ptrSz) || dataPtr > uintptr(unsafe.Pointer(&buf[len(buf)-1])) {
		return "", errors.New("invalid string")
	}*/

	return "\\\\?\\SystemPartition\\", nil
}
