//go:build !linux && !windows
// +build !linux,!windows

package srtmlog

import (
	"errors"
	"io"
	"runtime"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([][]byte, error) {
	return nil, errors.New("srtmlog.ReadTPM2EventLog not implemented on " + runtime.GOOS)
}

// dummy placeholder to allow windows errors to be mapped on win only
func mapErrors(err error) error {
	return err
}

func PCPQuoteKeys() ([]string, [][]byte, error) {
	return nil, nil, nil
}
