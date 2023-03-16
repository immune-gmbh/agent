package biosflash

import (
	"crypto/sha256"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
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
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(buf)
	flash.Sha256 = api.Buffer(sum[:])
	flash.ZData = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	return nil
}
