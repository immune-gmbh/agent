package tcg

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

func osOpenTPM(tpmPath string) (io.ReadWriteCloser, error) {
	conn, err := tpmutil.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
