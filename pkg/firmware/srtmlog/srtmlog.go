package srtmlog

import (
	"errors"
	"io"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
)

var ErrNoEventLog = common.ErrorNoResponse(errors.New("no event log found"))

func ReportTPM2EventLog(eventlog *api.ErrorBuffer, conn io.ReadWriteCloser) error {
	log.Trace().Msg("ReportTPM2EventLog()")

	buf, err := readTPM2EventLog(conn)
	if err != nil {
		log.Debug().Err(err).Msg("srtmlog.ReportTPM2EventLog()")
		log.Warn().Msg("Failed to read TPM 2.0 event log")
		//XXX map tpmutil errors
		eventlog.Error = common.ServeApiError(mapErrors(common.MapFSErrors(err)))
		return err
	}

	if len(buf) > 0 {
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			return err
		}
		eventlog.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	}

	return nil
}

func ReportPCPQuoteKeys() (map[string]api.Buffer, error) {
	quoteKeys := make(map[string]api.Buffer)
	names, blobs, err := PCPQuoteKeys()
	if err != nil {
		log.Debug().Err(err).Msg("srtmlog.PCPQuoteKeys()")
		log.Warn().Msg("Failed to read PCP quote keys")
	} else if len(names) == len(blobs) && len(names) > 0 {
		for i, name := range names {
			quoteKeys[name] = blobs[i]
		}
		return quoteKeys, nil
	}

	return nil, nil
}
