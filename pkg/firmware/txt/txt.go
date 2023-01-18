package txt

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func ReportTXTPublicSpace(pubSpace *api.ErrorBuffer) error {
	log.Trace().Msg("ReportTXTPublicSpace()")

	buf, err := readTXTPublicSpace()
	if err != nil {
		pubSpace.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Msgf("txt.ReportTXTPublicSpace(): %s", err.Error())
		log.Warn().Msgf("Failed to get Intel TXT public space")
		return err
	}
	pubSpace.Data = buf
	return nil
}
