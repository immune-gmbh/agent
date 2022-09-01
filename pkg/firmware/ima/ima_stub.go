//go:build !linux

package ima

import (
	"errors"
	"runtime"
)

func readIMALog() ([]byte, error) {
	return nil, errors.New("ima.readIMALog not implemented on " + runtime.GOOS)
}
