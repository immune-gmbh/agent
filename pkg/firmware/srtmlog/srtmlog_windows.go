package srtmlog

import (
	"io"
	"syscall"
	"unsafe"

	"github.com/google/go-tpm/tpmutil/tbs"
)

const TBS_GET_ALL_LOGS_FLAG = 1

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

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	// Run command first with nil buffer to get required buffer size.
	logLen, tbsErr := getAllTCGLogs(nil)
	if tbsErr != 0 {
		return nil, error(tbsErr)
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
			continue
		}
		break
	}

	// fall back to just getting the current event log
	if tbsErr == tbs.ErrInsufficientBuffer {
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
		logBuffer = make([]byte, logLen)
		if _, err = context.GetTCGLog(logBuffer); err != nil {
			return nil, err
		}
	}

	return logBuffer, nil
}
