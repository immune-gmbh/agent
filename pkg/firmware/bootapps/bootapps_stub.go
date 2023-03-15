//go:build !linux && !windows

package bootapps

import (
	"errors"
	"runtime"
)

func getEfiSystemPartPath() (string, error) {
	return "", errors.New("bootapps.getEfiSystemPartPath not implemented on " + runtime.GOOS)
}
