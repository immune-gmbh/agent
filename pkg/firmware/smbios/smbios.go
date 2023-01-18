package smbios

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func ReportSMBIOS(table *api.ErrorBuffer) error {
	log.Trace().Msg("ReportSMBIOS()")

	buf, err := readSMBIOS()
	if err != nil {
		table.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Msgf("smbios.ReportSMBIOS(): %s", err.Error())
		log.Warn().Msgf("Failed to get SMBIOS tables")
		return err
	}
	table.Data = buf
	return nil
}
