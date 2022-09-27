package srtmlog

import (
	"encoding/binary"
	"io"
	"os"
	"path"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	f, ok := conn.(*os.File)
	if ok {
		p := path.Join("/sys/kernel/security/", path.Base(f.Name()), "/binary_bios_measurements")
		buf, err := os.ReadFile(p)
		if len(buf) == 0 {
			return nil, ErrNoEventLog
		}
		newBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(newBuf, uint32(len(buf)))
		return append(newBuf, buf...), err
	}

	return nil, ErrNoEventLog
}

// dummy placeholder to allow windows errors to be mapped on win only
func mapErrors(err error) error {
	return err
}
