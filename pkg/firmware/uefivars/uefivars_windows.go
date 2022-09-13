package uefivars

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	defaultBufferSz = 8192        // must be multiple of 2
	maxBufferSz     = 1024 * 1024 // must be multiple of 2
)

var (
	libKernel32 = syscall.NewLazyDLL("kernel32.dll")

	// MSDN Documentation for EnumSystemFirmwareTables:
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa
	procGetFirmwareEnvironmentVariableExA = libKernel32.NewProc("GetFirmwareEnvironmentVariableExA")
)

func readUEFIVariable(name, guid string) ([]byte, error) {
	buf, _, err := readUEFIVariableGUID(name, fmt.Sprintf("{%s}", strings.ToUpper(guid)))
	return buf, err
}

func readUEFIVariableGUID(name, guid string) ([]byte, uint32, error) {
	for i := defaultBufferSz; i <= maxBufferSz; i = i << 1 {
		var attr uint32
		bufSz := i
		buf := make([]byte, bufSz)
		bName := append([]byte(name), 0)
		bGuid := append([]byte(guid), 0)

		// calling with NULL buffer will return required buffer size
		r1, _, err := procGetFirmwareEnvironmentVariableExA.Call(
			uintptr(unsafe.Pointer(&bName[0])), // lpName
			uintptr(unsafe.Pointer(&bGuid[0])), // lpGuid
			uintptr(unsafe.Pointer(&buf[0])),   // pBuffer = NULL
			uintptr(bufSz),                     // nSize = 0
			uintptr(attr),                      // pdwAttribubutes = NULL
		)

		// err is never nil, must check r1, see doc here
		// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
		if r1 == 0 {
			var errNoErr syscall.Errno
			if errors.As(err, &errNoErr) {
				if errNoErr == syscall.ERROR_INSUFFICIENT_BUFFER {
					continue
				}
			}
			return nil, 0, fmt.Errorf("failed to get UEFI var: %w", err)
		}

		return buf[:uint32(r1)], attr, nil
	}

	return nil, 0, fmt.Errorf("failed to get UEFI var: %w", syscall.ERROR_INSUFFICIENT_BUFFER)
}
