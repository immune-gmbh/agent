//go:build linux || darwin || !windows
// +build linux darwin !windows

package state

import "path/filepath"

// Defaults for Linux and MacOS
const (
	// gloablProgramStateDir stores programatically generated state
	globalProgramStateDir string = "/var/lib"
	defaultTPMDevice      string = "/dev/tpm0"
)

func DefaultTPMDevice() string {
	return defaultTPMDevice
}

func DefaultStateDir() string {
	return filepath.Clean(filepath.Join(globalProgramStateDir, DefaultVendorSubdir))
}
