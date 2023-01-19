package cli

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/immune-gmbh/agent/v3/pkg/api"
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

	if err := agentCore.OpenTPM(); err != nil {
		log.Error().Msgf("Cannot open TPM: %s", agentCore.State.TPM)
		return err
	}

	return doAttest(agentCore, ctx, attest.Dump, attest.DryRun)
}

func doAttest(agentCore *core.AttestationClient, ctx context.Context, dumpReportTo string, dryRun bool) error {
	appraisal, webLink, err := agentCore.Attest(ctx, dumpReportTo, dryRun)
	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	inProgress := appraisal == nil

	if inProgress {
		tui.SetUIState(tui.StAttestationRunning)
		log.Info().Msg("Attestation in progress, results become available later")
		tui.ShowAppraisalLink(webLink)
		if webLink != "" {
			log.Info().Msgf("See detailed results here: %s", webLink)
		}
		return nil
	} else {
		tui.SetUIState(tui.StAttestationSuccess)
		log.Info().Msg("Attestation successful")
	}

	if dryRun {
		return nil
	}

	// setting these states will just toggle internal flags in tui
	// which later affect the trust chain render
	if appraisal.Verdict.SupplyChain == api.Unsupported {
		tui.SetUIState(tui.StTscUnsupported)
	}
	if appraisal.Verdict.EndpointProtection == api.Unsupported {
		tui.SetUIState(tui.StEppUnsupported)
	}

	if appraisal.Verdict.Result == api.Trusted {
		tui.SetUIState(tui.StDeviceTrusted)
		tui.SetUIState(tui.StChainAllGood)
	} else {
		tui.SetUIState(tui.StDeviceVulnerable)
		if appraisal.Verdict.SupplyChain == api.Vulnerable {
			tui.SetUIState(tui.StChainFailSupplyChain)
		} else if appraisal.Verdict.Configuration == api.Vulnerable {
			tui.SetUIState(tui.StChainFailConfiguration)
		} else if appraisal.Verdict.Firmware == api.Vulnerable {
			tui.SetUIState(tui.StChainFailFirmware)
		} else if appraisal.Verdict.Bootloader == api.Vulnerable {
			tui.SetUIState(tui.StChainFailBootloader)
		} else if appraisal.Verdict.OperatingSystem == api.Vulnerable {
			tui.SetUIState(tui.StChainFailOperatingSystem)
		} else if appraisal.Verdict.EndpointProtection == api.Vulnerable {
			tui.SetUIState(tui.StChainFailEndpointProtection)
		}
	}

	tui.ShowAppraisalLink(webLink)
	if webLink != "" {
		log.Info().Msgf("See detailed results here: %s", webLink)
	}

	if appraisal, err := json.MarshalIndent(*appraisal, "", "  "); err == nil {
		log.Debug().Msg(string(appraisal))
	}

	return nil
}
