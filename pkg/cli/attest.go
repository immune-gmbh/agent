package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/ipc"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/rs/zerolog/log"
)

type attestCmd struct {
	DryRun     bool   `name:"dry-run" help:"Do full attest but don't contact the immune servers" default:"false"`
	Dump       string `optional:"" name:"dump-report" help:"Specify a file to dump the security report to" type:"path"`
	Standalone bool   `help:"Don't connect to windows service to run attest"`
}

func (attest *attestCmd) winSvcAttest(ctx context.Context, stdLogOut io.Writer) error {
	client, _, err := ipc.ConnectNamedPipe(ctx, stdLogOut)
	if err != nil {
		log.Error().Err(err).Msg("failed to connect to server")
		return err
	}
	defer client.Shutdown()

	if reply, err := client.Attest(ipc.CmdArgsAttest{DryRun: attest.DryRun}); err != nil {
		log.Error().Err(err).Msg("failed to attest on remote server")
		return err
	} else if len(reply.Status) > 0 {
		// XXX this does not result in errors that compare well with errors.Is()
		return errors.New(reply.Status)
	}

	return nil
}

func (attest *attestCmd) Run(agentCore *core.AttestationClient, stdLogOut *io.Writer) error {
	ctx := context.Background()

	runSvcClient := runtime.GOOS == "windows" && !attest.Standalone

	var err error
	var evidence *api.Evidence
	if runSvcClient {
		err = attest.winSvcAttest(ctx, *stdLogOut)
	} else {
		if !agentCore.State.IsEnrolled() {
			log.Error().Msg("No previous state found, please enroll first.")
			return errors.New("no-state")
		}

		evidence, err = agentCore.Attest(ctx, attest.DryRun)
	}

	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	if !runSvcClient && attest.Dump != "" && evidence != nil {
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
