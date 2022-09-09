package srtmlog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/google/go-tpm/tpmutil/tbs"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TBS_GET_ALL_LOGS_FLAG = 1

	// the default directory under the windows root directory that holds WBCL logs
	defaultWBCLSubDirectory = "Logs\\MeasuredBoot"

	// this key holds various TPM (driver) related info; relative to HKLM
	regKeyTPM = "System\\CurrentControlSet\\services\\TPM"

	// alternate WBCL log path can be specified with the following value under TPM key
	regValAlternateWBCLPath = "WBCLPath" // optional

	// this values hold the current OS boot and resume count under the TPM key
	regValOsBootCount   = "OsBootCount"
	regValOsResumeCount = "OsResumeCount" // optional
)

// use windows TPM base services DLL to call Tbsi_Get_TCG_Logs
// https://docs.microsoft.com/en-us/windows/win32/tbs/tbs-functions
var (
	tbsDLL        = syscall.NewLazyDLL("Tbs.dll")
	tbsGetTCGLogs = tbsDLL.NewProc("Tbsi_Get_TCG_Logs")
)

// getError is copied from go-tpm library
func getError(err uintptr) tbs.Error {
	// tbs.dll uses 0x0 as the return value for success.
	return tbs.Error(err)
}

// sliceAddress is copied from go-tpm library
// Returns the address of the beginning of a slice or 0 for a nil slice.
func sliceAddress(s []byte) uintptr {
	if len(s) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&(s[0])))
}

// GetAllTCGLogs gets all WBCL logs from last boot up to most recent resume.
// Pass nil logBuffer to get the size required to store all logs.
// ErrInsufficientBuffer is returned if the logBuffer is too short. On failure,
// the returned length is unspecified.
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/dn455156(v=vs.85)
func getAllTCGLogs(logBuffer []byte) (uint32, tbs.Error) {
	var logBufferLenNew uint32
	logBufferLen := uint32(len(logBuffer))

	// TBS_RESULT Tbsi_Get_TCG_Logs(
	//   UINT32     firstLog,
	//   PUINT32    pNextLog,
	//   PBYTE      pbOutput,
	//   UINT32     cbOutput,
	//   PUINT32    pcbResult,
	//   UINT32     dwFlags
	// );
	result, _, _ := tbsGetTCGLogs.Call(
		0,
		uintptr(0),
		sliceAddress(logBuffer),
		uintptr(unsafe.Pointer(&logBufferLen)),
		uintptr(unsafe.Pointer(&logBufferLenNew)),
		TBS_GET_ALL_LOGS_FLAG)

	return logBufferLenNew, getError(result)
}

func getDefaultWBCLPath() (string, error) {
	winDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(winDir, defaultWBCLSubDirectory), nil
}

func getWBCLPathAndBootCount() (string, uint64, uint64, error) {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyTPM, uint32(registry.QUERY_VALUE))
	if err != nil {
		return "", 0, 0, err
	}
	defer regKey.Close()

	wbclPath, _, err := regKey.GetStringValue(regValAlternateWBCLPath)
	// if the alternate WBCL path isn't specified we use the default one
	if err == registry.ErrNotExist {
		wbclPath, err = getDefaultWBCLPath()
		if err != nil {
			return "", 0, 0, err
		}
	} else if err != nil {
		return "", 0, 0, err
	}

	osBootCount, _, err := regKey.GetIntegerValue(regValOsBootCount)
	if err != nil {
		return "", 0, 0, err
	}

	osResumeCount, _, err := regKey.GetIntegerValue(regValOsResumeCount)
	// if the OS can not hibernate then there is no resume count (applies to servers)
	if err == registry.ErrNotExist {
		osResumeCount = 0
	} else if err != nil {
		return "", 0, 0, err
	}

	return wbclPath, osBootCount, osResumeCount, nil
}

func makeWBCLFilePath(wbclPath string, bootCount, resumeCount uint32) string {
	return filepath.Join(wbclPath, fmt.Sprintf("%010d-%010d.log", bootCount, resumeCount))
}

// try to get the WBCL logs from a known location on disk
// the disk storage is also what is used by most windows TBS functions
func getAllWBCLLogsFromDisk() ([]byte, error) {
	wbclPath, osBootCount, osResumeCount, err := getWBCLPathAndBootCount()
	if err != nil {
		return nil, err
	}

	// check reasonable counter values
	if osBootCount > math.MaxUint32 {
		return nil, errors.New("boot counter too large")
	}
	if osResumeCount > math.MaxUint16 {
		return nil, errors.New("resume counter too large")
	}

	// see if boot log exists under current dir, otherwise try default dir
	if _, err := os.Stat(makeWBCLFilePath(wbclPath, uint32(osBootCount), 0)); errors.Is(err, os.ErrNotExist) {
		logrus.Tracef("srtmlog.getAllWBCLLogsFromDisk(): alternate WBCL path not working: %v", wbclPath)
		wbclPath, err = getDefaultWBCLPath()
		if err != nil {
			return nil, err
		}
		logrus.Tracef("srtmlog.getAllWBCLLogsFromDisk(): falling back to default WBCL path: %v", wbclPath)
	} else if err != nil {
		return nil, err
	}

	// see if boot log exists in default dir
	if _, err := os.Stat(makeWBCLFilePath(wbclPath, uint32(osBootCount), 0)); err != nil {
		return nil, err
	}

	// get all logs up to the most recent resume
	var concatWBCL []byte
	for resume := uint32(0); resume <= uint32(osResumeCount); resume++ {
		buf, err := os.ReadFile(makeWBCLFilePath(wbclPath, uint32(osBootCount), uint32(resume)))
		if err != nil {
			return nil, err
		}

		prefix := make([]byte, 4)
		binary.LittleEndian.PutUint32(prefix, uint32(len(buf)))
		concatWBCL = append(concatWBCL, prefix...)
		concatWBCL = append(concatWBCL, buf...)
	}

	return concatWBCL, nil
}

// try to obtain WBCLs using windows API functions
func readTPM2EventLogWinApi(conn io.ReadWriteCloser) ([]byte, error) {
	// Run command first with nil buffer to get required buffer size.
	logLen, tbsErr := getAllTCGLogs(nil)
	if tbsErr != 0 {
		return nil, error(tbsErr)
	}

	if logLen == 0 {
		return nil, ErrNoEventLog
	}

	// logBuffer may hold multiple concatenated logs (boot log + hibernate/resume logs)
	logBuffer := make([]byte, logLen)

	// sometimes windows complains that the buffer was too small,
	// even though it has the size we were told to allocate. In that
	// case we simply retry, it often works.
	for retry := 0; retry < 3; retry = retry + 1 {
		if _, tbsErr = getAllTCGLogs(logBuffer); tbsErr != 0 {

			// we will still get the right amount of data and in that case
			// we simply ignore the error
			if tbsErr != tbs.ErrInsufficientBuffer {
				return nil, error(tbsErr)
			}
			logrus.Trace("srtmlog.readTPM2EventLogWinApi(): retrying getAllTCGLogs()")
			continue
		}

		// trim end marker
		if len(logBuffer) > 3 || binary.LittleEndian.Uint32(logBuffer[len(logBuffer)-4:]) == 0xFFFFFFFF {
			logBuffer = logBuffer[:len(logBuffer)-4]
		}

		break
	}

	// fall back to just getting the current event log
	if tbsErr == tbs.ErrInsufficientBuffer {
		logrus.Debug("srtmlog.getAllTCGLogs(): failed, falling back to getting only current TCG log")
		context, err := tbs.CreateContext(tbs.TPMVersion20, tbs.IncludeTPM20|tbs.IncludeTPM12)
		if err != nil {
			return nil, err
		}
		defer context.Close()

		// Run command first with nil buffer to get required buffer size.
		logLen, err = context.GetTCGLog(nil)
		if err != nil {
			return nil, err
		}
		if logLen == 0 {
			return nil, ErrNoEventLog
		}
		logBuffer = make([]byte, logLen)
		if _, err = context.GetTCGLog(logBuffer); err != nil {
			return nil, err
		}
		newBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(newBuf, uint32(len(logBuffer)))
		logBuffer = append(newBuf, logBuffer...)
	}

	return logBuffer, nil
}

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	// try to get all current WBCL logs from on-disk location first
	// this is more reliable than getAllTCGLogs() and more complete than GetTCGLog()
	logs, err := getAllWBCLLogsFromDisk()
	if err != nil {
		logrus.Debugf("srtmlog.getAllWBCLLogsFromDisk(): failed to get WBCLs from disk, falling back to API: %v", err)
		// try to use API functions as fallback
		logs, err = readTPM2EventLogWinApi(conn)
		if err != nil {
			return nil, err
		}
	}

	return logs, nil
}
