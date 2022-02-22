package netif

import (
	"net"
	"path/filepath"
	"strings"
)

func readMACAddresses() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	macAddrs := []string{}
	for _, ifa := range ifas {
		// exclude virtual interfaces
		dp, err := filepath.EvalSymlinks("/sys/class/net/" + ifa.Name)
		if err == nil && strings.Contains(dp, "/devices/virtual/") {
			continue
		}

		f := ifa.Flags
		if f&net.FlagLoopback != 0 {
			continue
		}
		if f&net.FlagPointToPoint != 0 {
			continue
		}

		s := ifa.HardwareAddr.String()
		if s == "" {
			continue
		}
		macAddrs = append(macAddrs, s)
	}
	return macAddrs, nil
}
