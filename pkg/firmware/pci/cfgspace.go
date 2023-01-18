package pci

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func reportConfigSpace(request *api.PCIConfigSpace) error {
	buf, err := readConfigSpace(uint32(request.Bus), uint32(request.Device), uint32(request.Function), 0, 4096)

	if err != nil {
		log.Debug().Msgf("pci.ReportConfigSpace(): %s", err.Error())
		request.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}
	request.Value = buf
	return nil
}

func ReportConfigSpaces(requests []api.PCIConfigSpace) (err error) {
	log.Trace().Msg("ReportConfigSpaces()")

	allFailed := true
	for i := range requests {
		v := &requests[i]
		err = reportConfigSpace(v)
		allFailed = allFailed && err != nil
	}
	if allFailed && len(requests) > 0 {
		log.Warn().Msgf("Failed to read PCI configuration space")
		return
	}
	err = nil
	return
}
