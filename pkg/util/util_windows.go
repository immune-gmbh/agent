package util

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows privilege constant
const SE_PRIVILEGE_ENABLED = 2

// lookupPrivilegeValue finds the LUID for a named privilege
func lookupPrivilegeValue(name string, luid *windows.LUID) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}

	return windows.LookupPrivilegeValue(nil, _p0, luid)
}

// WinAddTokenPrivilege adds a privilege to the security token of the current process
func WinAddTokenPrivilege(name string) error {
	p := windows.CurrentProcess()
	var token windows.Token
	err := windows.OpenProcessToken(p, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("can't open process token: %w", err)
	}

	var luid windows.LUID
	err = lookupPrivilegeValue(name, &luid)
	if err != nil {
		return fmt.Errorf("error looking up privilege LUID: %w", err)
	}

	var tp windows.Tokenprivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	err = windows.AdjustTokenPrivileges(windows.Token(token), false, &tp, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("AdjustTokenPrivileges err: %w", err)
	}

	return nil
}

func IsKernelModuleLoaded(name string) (bool, error) {
	return false, errors.New("IsKernelModuleLoaded not implemented on " + runtime.GOOS)
}

func IsRoot() (bool, error) {
	var sid *windows.SID

	// see https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid); err != nil {
		return false, fmt.Errorf("SID Error: %s", err)
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token error: %s", err)
	}

	return member, nil
}

func StartDriverIfNotRunning(driverName string) error {
	svcmgr, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer svcmgr.Disconnect()

	sv, err := svcmgr.OpenService(driverName)
	if err != nil {
		return err
	}
	defer sv.Close()

	status, err := sv.Query()
	if err != nil {
		return err
	}

	if status.State == svc.Running {
		return nil
	}

	err = sv.Start()
	if err != nil {
		return err
	}

	return nil
}

func StopDriver(driverName string) error {
	svcmgr, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer svcmgr.Disconnect()

	sv, err := svcmgr.OpenService(driverName)
	if err != nil {
		return err
	}
	defer sv.Close()

	status, err := sv.Query()
	if err != nil {
		return err
	}

	if status.State == svc.Stopped {
		return nil
	}

	_, err = sv.Control(svc.Stop)
	if err != nil {
		return err
	}

	return nil
}
