package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/ima"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/rs/zerolog/log"
)

type collectCmd struct {
}

func doCollect(ctx context.Context, cfg *api.Configuration) error {
	var conn io.ReadWriteCloser

	// collect firmware info
	tui.SetUIState(tui.StCollectFirmwareInfo)
	log.Info().Msg("Collecting firmware info")
	fwProps := firmware.GatherFirmwareData(conn, cfg)

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
	log.Info().Msgf("Dumped evidence json: %s", path)

	return nil
}

func (collect *collectCmd) Run(glob *core.AttestationClient) error {
	ctx := context.Background()
	cfg := api.Configuration{}

	err := doCollect(ctx, &cfg)
	if err != nil {
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	tui.SetUIState(tui.StAttestationSuccess)
	return nil
}
