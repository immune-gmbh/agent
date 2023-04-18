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
		log.Debug().Err(err).Msg("acpi.ReadACPITables()")
		log.Warn().Msg("Failed to get ACPI tables")
		return err
	}
	// map to cast []byte to api.Buffer
	acpiTables.Blobs = make(map[string]api.HashBlob)
	for k, v := range t {
		acpiTables.Blobs[k] = api.HashBlob{Data: v}
	}
	return nil
}
