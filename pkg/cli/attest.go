package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/rs/zerolog/log"
)

type attestCmd struct {
	DryRun bool   `name:"dry-run" help:"Do full attest but don't contact the immune servers" default:"false"`
	Dump   string `optional:"" name:"dump-report" help:"Specify a file to dump the security report to" type:"path"`
}

func (attest *attestCmd) Run(agentCore *core.AttestationClient) error {
	ctx := context.Background()

	if !agentCore.State.IsEnrolled() {
		log.Error().Msg("No previous state found, please enroll first.")
		return errors.New("no-state")
	}

	evidence, err := agentCore.Attest(ctx, attest.DryRun)
	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	if attest.Dump != "" && evidence != nil {
		evidenceJSON, err := json.Marshal(evidence)
		if err != nil {
			log.Debug().Err(err).Msg("json.Marshal(Evidence)")
			log.Error().Msg("Failed to dump report.")
			return err
		}

		if attest.Dump == "-" {
			fmt.Println(string(evidenceJSON))
		} else {
			path := attest.Dump + ".evidence.json"
			if err := os.WriteFile(path, evidenceJSON, 0644); err != nil {
				return err
			}
			log.Info().Msgf("Dumped evidence json: %s", path)
		}
	}

	return nil
}
