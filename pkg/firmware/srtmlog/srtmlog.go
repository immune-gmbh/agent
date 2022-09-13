package srtmlog

import (
	"errors"
	"io"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

var ErrNoEventLog = common.ErrorNoResponse(errors.New("no event log found"))

func ReportTPM2EventLog(log *api.ErrorBuffer, conn io.ReadWriteCloser) error {
	logrus.Traceln("ReportTPM2EventLog()")

	buf, err := readTPM2EventLog(conn)
	if err != nil {
		logrus.Debugf("srtmlog.ReportTPM2EventLog(): %s", err.Error())
		logrus.Warnf("Failed to read TPM 2.0 event log")
		//XXX map tpmutil errors
		log.Error = common.ServeApiError(mapErrors(common.MapFSErrors(err)))
		return err
	}

	if len(buf) > 0 {
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			return err
		}
		log.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	}

	return nil
}
