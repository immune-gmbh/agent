package ima

import (
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
)

func ReportIMALog(imaLog *api.ErrorBuffer) error {
	log.Trace().Msg("ReportIMALog()")

	buf, err := readIMALog()
	if err != nil {
		log.Debug().Msgf("ima.ReportIMALog(): %s", err.Error())
		log.Warn().Msgf("Failed to read Linux IMA runtime measurement log")
		imaLog.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	imaLog.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	return nil
}
