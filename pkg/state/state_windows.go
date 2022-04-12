package state

import (
	"os"
	"path/filepath"
)

const defaultTPMDevice = "system"

func DefaultTPMDevice() string {
	return defaultTPMDevice
}

// DefaultStateDir returns all candidates for the config data dir in order of
// writing.
func DefaultStateDir() string {
	return filepath.Clean(filepath.Join(os.Getenv("ProgramData"), DefaultVendorSubdir))
}
