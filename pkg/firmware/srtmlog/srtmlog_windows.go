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
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TBS_GET_ALL_LOGS_FLAG = 1

	// the default directory under the windows root directory that holds WBCL logs
	defaultWBCLSubDirectory = "Logs\\MeasuredBoot"

	// this key holds various TPM (driver) related info; relative to HKLM
	regKeyTPM = "System\\CurrentControlSet\\services\\TPM"

	// this key holds all registered AIKs used to quote boot + hibernate/resume event logs
	regKeyPlatformQuoteKeys = regKeyTPM + "\\PlatformQuoteKeys"

	// alternate WBCL log path can be specified with the following value under TPM key
	regValAlternateWBCLPath = "WBCLPath" // optional

	// this values hold the current OS boot and resume count under the TPM key
	regValOsBootCount = "OsBootCount"

	// this key holds various volatile TPM related info; relative to HKLM
	regKeyIntegrity = "System\\CurrentControlSet\\Control\\IntegrityServices"

	// this value holds the current WBCL
	regValWBCL = "WBCL"
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

func getWBCLPathAndBootCount() (string, uint64, error) {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyTPM, uint32(registry.QUERY_VALUE))
	if err != nil {
		return "", 0, err
	}
	defer regKey.Close()

	wbclPath, _, err := regKey.GetStringValue(regValAlternateWBCLPath)
	// if the alternate WBCL path isn't specified we use the default one
	if err == registry.ErrNotExist {
		wbclPath, err = getDefaultWBCLPath()
		if err != nil {
			return "", 0, err
		}
	} else if err != nil {
		return "", 0, err
	}

	osBootCount, _, err := regKey.GetIntegerValue(regValOsBootCount)
	if err != nil {
		return "", 0, err
	}

	return wbclPath, osBootCount, nil
}

func makeWBCLFilePattern(wbclPath string, bootCount uint32, resumeCount ...uint32) string {
	if len(resumeCount) > 0 {
		return filepath.Join(wbclPath, fmt.Sprintf("%010d-%010d.log", bootCount, resumeCount[0]))
	} else {
		return filepath.Join(wbclPath, fmt.Sprintf("%010d-??????????.log", bootCount))
	}
}

// try to get the WBCL logs from a known location on disk
// the disk storage is also what is used by most windows TBS functions
func getAllWBCLLogsFromDisk() ([]byte, error) {
	wbclPath, osBootCount, err := getWBCLPathAndBootCount()
	if err != nil {
		return nil, err
	}

	// check reasonable counter values
	if osBootCount > math.MaxUint32 {
		return nil, errors.New("boot counter too large")
	}

	// see if boot log exists under current dir, otherwise try default dir
	if _, err := os.Stat(makeWBCLFilePattern(wbclPath, uint32(osBootCount), 0)); errors.Is(err, os.ErrNotExist) {
		log.Trace().Msgf("srtmlog.getAllWBCLLogsFromDisk(): alternate WBCL path not working: %v", wbclPath)
		wbclPath, err = getDefaultWBCLPath()
		if err != nil {
			return nil, err
		}
		log.Trace().Msgf("srtmlog.getAllWBCLLogsFromDisk(): falling back to default WBCL path: %v", wbclPath)
	} else if err != nil {
		return nil, err
	}

	// see if boot log exists in default dir
	if _, err := os.Stat(makeWBCLFilePattern(wbclPath, uint32(osBootCount), 0)); err != nil {
		return nil, err
	}

	// get all logs up to the most recent resume
	var concatWBCL []byte
	paths, err := filepath.Glob(makeWBCLFilePattern(wbclPath, uint32(osBootCount)))
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		buf, err := os.ReadFile(p)
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
			log.Trace().Msg("srtmlog.readTPM2EventLogWinApi(): retrying getAllTCGLogs()")
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
		log.Debug().Msg("srtmlog.getAllTCGLogs(): failed, falling back to getting only current TCG log")
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

// try to obtain current WBCL from registry
func readTPM2EventLogRegistry() ([]byte, error) {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyIntegrity, uint32(registry.QUERY_VALUE))
	if err != nil {
		return nil, err
	}
	defer regKey.Close()

	val, _, err := regKey.GetBinaryValue(regValWBCL)
	if err != nil {
		return nil, err
	}

	newBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(newBuf, uint32(len(val)))
	val = append(newBuf, val...)

	return val, nil
}

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	// try to get all current WBCL logs from on-disk location first
	// this is more reliable than getAllTCGLogs() and more complete than GetTCGLog()
	logs, err := getAllWBCLLogsFromDisk()
	if err != nil {
		log.Debug().Err(err).Msg("srtmlog.getAllWBCLLogsFromDisk(): failed to get WBCLs from disk, falling back to API: %v")

		// try to use API functions as fallback
		logs, err = readTPM2EventLogWinApi(conn)
		if err != nil {
			log.Debug().Err(err).Msg("srtmlog.readTPM2EventLogWinApi(): failed to get WBCLs from API, falling back to registry key: %v")

			// try getting current WBCL from registry as fallback
			return readTPM2EventLogRegistry()
		}
	}

	return logs, nil
}

func mapErrors(err error) error {
	return common.MapTBSErrors(err)
}

// grab Platform Crypto Provider AIKs registered to quote boot and hibernate/resume event logs
func PCPQuoteKeys() ([]string, [][]byte, error) {
	regKey, err := registry.OpenKey(registry.LOCAL_MACHINE, regKeyPlatformQuoteKeys, uint32(registry.QUERY_VALUE))
	if err != nil {
		return nil, nil, err
	}
	defer regKey.Close()

	valNames, err := regKey.ReadValueNames(-1)
	if err != nil {
		return nil, nil, err
	}

	names, keys := []string{}, [][]byte{}
	for _, keyName := range valNames {
		keyBlob, _, err := regKey.GetBinaryValue(keyName)
		if err == nil {
			names = append(names, keyName)
			keys = append(keys, keyBlob)
		}
	}

	return names, keys, nil
}
