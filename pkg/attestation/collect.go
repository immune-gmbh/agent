package attestation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/ima"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func Collect(ctx context.Context, cfg *api.Configuration) error {
	var conn io.ReadWriteCloser

	// collect firmware info
	tui.SetUIState(tui.StCollectFirmwareInfo)
	log.Info("Collecting firmware info")
	fwProps, err := firmware.GatherFirmwareData(conn, cfg)
	if err != nil {
		return err
	}

	// fetch the runtime measurment log
	fwProps.IMALog = new(api.ErrorBuffer)
	ima.ReportIMALog(fwProps.IMALog)

	cookie, _ := api.Cookie(rand.Reader)
	evidence := api.Evidence{
		Type:      api.EvidenceType,
		Algorithm: strconv.Itoa(int(cfg.PCRBank)),
		Firmware:  fwProps,
		Cookie:    cookie,
	}

	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return err
	}

	path := "collector.evidence.json"
	if err := os.WriteFile(path, evidenceJSON, 0644); err != nil {
		return err
	}
	log.Infof("Dumped evidence json: %s", path)

	return nil
}
