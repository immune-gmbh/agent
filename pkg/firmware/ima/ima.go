package ima

import (
	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
)

func ReportIMALog(log *api.ErrorBuffer) error {
	logrus.Traceln("ReportIMALog()")

	buf, err := readIMALog()
	if err != nil {
		logrus.Debugf("ima.ReportIMALog(): %s", err.Error())
		logrus.Warnf("Failed to read Linux IMA runtime measurement log")
		log.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	log.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	return nil
}
