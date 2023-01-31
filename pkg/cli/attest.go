package cli

import (
	"context"
	"errors"

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

	err := agentCore.Attest(ctx, attest.Dump, attest.DryRun)
	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	return nil
}
