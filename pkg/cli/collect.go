package cli

import (
	"context"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/attestation"
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

type collectCmd struct {
}

func (collect *collectCmd) Run(glob *core.GlobalOptions) error {
	ctx := context.Background()
	cfg := api.Configuration{}

	err := attestation.Collect(ctx, &cfg)
	if err != nil {
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	tui.SetUIState(tui.StAttestationSuccess)
	return nil
}
