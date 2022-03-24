package tcg

import (
	"fmt"
	"io"
)

const defaultTPMDevice = "none"

func DefaultTPMDevice() string {
	return defaultTPMDevice
}

func osOpenTPM(tpmPath string) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("Not implemented yet")
}
