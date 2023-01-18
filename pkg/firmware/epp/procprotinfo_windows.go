package epp

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

const (
	queryLimitedInformation      = 0x00001000
	processProtectionInformation = 0x0000003D
)

type PsProtectedType uint32

const (
	TypeNone PsProtectedType = iota
	TypeProtectedLight
	TypeProtected
	TypeMax
)

var protectedTypeStr = []string{
	"None",
	"ProtectedLight",
	"Protected",
	"Max",
}

func (val PsProtectedType) String() string {
	if val < 4 {
		return protectedTypeStr[val]
	} else {
		return "invalid"
	}
}

type PsProtectedSigner uint32

const (
	SignerNone PsProtectedSigner = iota
	SignerAuthenticode
	SignerCodeGen
	SignerAntimalware
	SignerLsa
	SignerWindows
	SignerWinTcb
	SignerMax
)

var protectedSignerStr = []string{
	"None",
	"Authenticode",
	"CodeGen",
	"Antimalware",
	"Lsa",
	"Windows",
	"WinTcb",
	"Max",
}

func (val PsProtectedSigner) String() string {
	if val < 8 {
		return protectedSignerStr[val]
	} else {
		return "invalid"
	}
}

var (
	ntDLL = syscall.NewLazyDLL("ntdll.dll")

	// MSDN Documentation for NtQueryInformationProcess:
	// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess2/nf-cfgmgr32-cm_get_device_interface_list_sizea
	// This is an internal function and thus it is subject to change
	ntQueryInformationProcess = ntDLL.NewProc("NtQueryInformationProcess")
)

func queryInformationProcess(procHandle windows.Handle, processInformationClass uint32, processInformation []byte) (uint32, error) {
	var retLen uint32

	r1, _, err := ntQueryInformationProcess.Call(
		uintptr(procHandle),                             // HANDLE ProcessHandle
		uintptr(processInformationClass),                // PROCESSINFOCLASS ProcessInformationClass
		uintptr(unsafe.Pointer(&processInformation[0])), // PVOID ProcessInformation
		uintptr(len(processInformation)),                // ULONG ProcessInformationLength
		uintptr(unsafe.Pointer(&retLen)),                // PULONG ReturnLength
	)

	// err is never nil, must check r1, see doc here
	// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
	if r1 != 0 {
		return 0, err
	}

	return retLen, nil
}

func queryFullProcessImageName(procHandle windows.Handle) (string, error) {
	for i := 2048; i <= 32768; i = i << 1 {
		exeNameU16 := make([]uint16, i)
		exeNameSz := uint32(len(exeNameU16))
		err := windows.QueryFullProcessImageName(procHandle, 0, &exeNameU16[0], &exeNameSz)
		if err != nil {
			return "", err
		}

		// if we got less data than our buffer is long then probably we have the full name
		// (the count we get returned is without the null termination)
		if exeNameSz < uint32((i - 1)) {
			return syscall.UTF16ToString(exeNameU16), nil
		}
	}

	return "", errors.New("image name buffer too small")
}

func QueryProcessProtectionLvl(procHandle windows.Handle) (PsProtectedType, PsProtectedSigner, error) {
	buf := make([]byte, 1)
	retLen, err := queryInformationProcess(procHandle, processProtectionInformation, buf)
	if err != nil {
		return 0, 0, err
	}
	if retLen != 1 {
		return 0, 0, errors.New("wrong return size")
	}

	return PsProtectedType(buf[0] & 0x07), PsProtectedSigner((buf[0] & 0xf0) >> 4), nil
}

func enumProcesses() ([]uint32, error) {
	for i := 1024; i <= 32768; i = i << 1 {
		var bytesReturned uint32
		processIds := make([]uint32, i)
		err := windows.EnumProcesses(processIds, &bytesReturned)
		if err != nil {
			return nil, err
		}

		// if we got less data than our buffer is long then probably we have all processes
		if int(bytesReturned/4) < i {
			return processIds[:(bytesReturned / 4)], nil
		}
	}

	return nil, errors.New("process list buffer too small")
}

func getFullImagePathOnlyIfPPLProc(processId uint32) (string, error) {
	procHandle, err := windows.OpenProcess(queryLimitedInformation, false, processId)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(procHandle)

	lvl, sig, err := QueryProcessProtectionLvl(procHandle)
	if err != nil {
		return "", err
	}

	if lvl == TypeProtectedLight && sig == SignerAntimalware {
		name, err := queryFullProcessImageName(procHandle)
		return name, err
	}

	return "", nil
}

// ListPPLProcessImagePaths lists image paths of processes with process protection light enabled
func ListPPLProcessImagePaths() ([]string, error) {
	procIds, err := enumProcesses()
	if err != nil {
		return nil, err
	}

	var list []string
	for _, id := range procIds {
		name, err := getFullImagePathOnlyIfPPLProc(id)
		if name == "" {
			continue
		}
		if err == nil {
			list = append(list, name)
		} else {
			log.Trace().Msgf("epp.getFullImagePathOnlyIfPPLProc(): procId #%v %s", id, err.Error())
		}
	}

	return list, nil
}
