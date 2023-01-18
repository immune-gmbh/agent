package epp

import (
	"os"

	"github.com/rs/zerolog/log"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
)

func ReportEPP(eppInfo *api.EPPInfo) error {
	_, err := os.Stat("/sys/module/eset_rtp/refcnt")
	if os.IsNotExist(err) {
		log.Trace().Msg("eset_rtp module not loaded")
		return nil
	}

	var eset api.ESETConfig

	data, err := os.ReadFile("/sys/module/eset_rtp/settings/enable")
	eset.Enabled.Data = api.Buffer(data)
	if err != nil {
		log.Debug().Err(err).Msg("reading settings/enable")
		eset.Enabled.Error = common.ServeApiError(common.MapFSErrors(err))
	}
	data, err = os.ReadFile("/sys/module/eset_rtp/settings/excludes/files")
	eset.ExcludedFiles.Data = api.Buffer(data)
	if err != nil {
		log.Debug().Err(err).Msg("reading settings/excludes/files")
		eset.ExcludedFiles.Error = common.ServeApiError(common.MapFSErrors(err))
	}
	data, err = os.ReadFile("/sys/module/eset_rtp/settings/excludes/procs")
	eset.ExcludedProcesses.Data = api.Buffer(data)
	if err != nil {
		log.Debug().Err(err).Msg("reading settings/excludes/procs")
		eset.ExcludedProcesses.Error = common.ServeApiError(common.MapFSErrors(err))
	}

	eppInfo.ESET = &eset
	return nil
}
