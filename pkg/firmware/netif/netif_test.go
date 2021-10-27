package netif

import (
	"regexp"
	"runtime"
	"testing"
)

func TestReportMacAddrs(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("not implemented on OSX")
	}

	macAddrs, err := readMACAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(macAddrs) == 0 {
		t.Fatalf("no mac addresses")
	}
	for i, addr := range macAddrs {
		if m, err := regexp.MatchString("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", addr); err != nil || !m {
			t.Fatalf("MAC address %d ('%s') is not valid", i, addr)
		}
	}
}
