package tcg

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

func osOpenTPM(tpmPath string) (io.ReadWriteCloser, error) {
	_ = tpmPath
	conn, err := tpmutil.OpenTPM()
	if err != nil {
		return nil, err
	}
	return conn, nil
}
