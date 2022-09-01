package srtmlog

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"path"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	f, ok := conn.(*os.File)
	if ok {
		p := path.Join("/sys/kernel/security/", path.Base(f.Name()), "/binary_bios_measurements")
		buf, err := ioutil.ReadFile(p)
		if len(buf) == 0 {
			return nil, ErrNoEventLog
		}
		newBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(newBuf, uint32(len(buf)))
		return append(newBuf, buf...), err
	}

	return nil, ErrNoEventLog
}
