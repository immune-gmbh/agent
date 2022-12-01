//go:build !windows

package immunecpu

func CreateService() error { return nil }
func RemoveService() error { return nil }
func StopDriver() error    { return nil }
