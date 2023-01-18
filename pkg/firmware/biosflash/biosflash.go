package biosflash

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
)

func ReportBiosFlash(flash *api.ErrorBuffer) error {
	log.Trace().Msg("ReportBiosFlash()")

	buf, err := readBiosFlashMMap()
	if err != nil {
		flash.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Msgf("biosflash.ReportBiosFlash(): %s", err.Error())
		log.Warn().Msgf("Failed to read UEFI/BIOS flash")
		return err
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	flash.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	return nil
}
