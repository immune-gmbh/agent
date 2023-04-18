package biosflash

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func ReportBiosFlash(flash *api.HashBlob) error {
	log.Trace().Msg("ReportBiosFlash()")

	buf, err := readBiosFlashMMap()
	if err != nil {
		flash.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("biosflash.ReportBiosFlash()")
		log.Warn().Msg("Failed to read UEFI/BIOS flash")
		return err
	}
	flash.Data = buf
	return nil
}
