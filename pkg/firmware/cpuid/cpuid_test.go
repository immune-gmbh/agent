package cpuid

import (
	"runtime"
	"testing"

	"github.com/immune-gmbh/agent/v2/pkg/util"
)

func TestReadCPUID(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("only implemented on AMD64")
	}

	// retrieve processor manufacturer ID and check against known values
	eax, ebx, ecx, edx := readCPUID(0, 0)
	if eax < 2 {
		t.Error("EAX return value too low (<2)")
	}

	idstr := util.Uint32ToStr(ebx) + util.Uint32ToStr(edx) + util.Uint32ToStr(ecx)
	switch idstr {
	case "GenuineIntel":
	case "AuthenticAMD":
	default:
		t.Errorf("Unexpected processor type %s", idstr)
	}
}
