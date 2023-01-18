package cpuid

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/util"
	"github.com/rs/zerolog/log"
)

type CPUVendor uint

const (
	VendorOther CPUVendor = iota
	VendorIntel           = iota
	VendorAMD             = iota
)

var vendorMap = map[string]CPUVendor{
	"GenuineIntel": VendorIntel,
	"AuthenticAMD": VendorAMD,
}

func ReportCPUIDLeaf(leaf *api.CPUIDLeaf) {
	log.Trace().Msg("ReportCPUIDLeaf()")

	eax, ebx, ecx, edx := readCPUID(leaf.LeafEAX, leaf.LeafECX)

	leaf.EAX = &eax
	leaf.EBX = &ebx
	leaf.ECX = &ecx
	leaf.EDX = &edx
}

func Vendor() CPUVendor {
	_, ebx, ecx, edx := readCPUID(0, 0)
	idstr := util.Uint32ToStr(ebx) + util.Uint32ToStr(edx) + util.Uint32ToStr(ecx)
	val, ok := vendorMap[idstr]
	if ok {
		return val
	}
	return VendorOther
}
