package acpi

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func ReportACPITables(acpiTables *api.ACPITables) error {
	log.Trace().Msg("ReportACPITables()")

	t, err := readACPITables()
	if err != nil {
		acpiTables.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Msgf("acpi.ReadACPITables(): %s", err.Error())
		log.Warn().Msgf("Failed to get ACPI tables")
		return err
	}
	// map map to cast []byte to api.Buffer
	acpiTables.Tables = make(map[string]api.Buffer)
	for k, v := range t {
		acpiTables.Tables[k] = v
	}
	return nil
}
