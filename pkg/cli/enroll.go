package cli

import (
	"context"
	"io"
	"net/url"
	"os"
	"runtime"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/ipc"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/rs/zerolog/log"
)

type enrollCmd struct {
	Server     *url.URL `name:"server" help:"immune SaaS API URL" type:"*url.URL"`
	NoAttest   bool     `help:"Don't attest after successful enrollment" default:"false"`
	Token      string   `arg:"" required:"" name:"token" help:"Enrollment authentication token"`
	Name       string   `arg:"" optional:"" name:"name hint" help:"Name to assign to the device. May get suffixed by a counter if already taken. Defaults to the hostname."`
	TPM        string   `name:"tpm" default:"${tpm_default_path}" help:"TPM device: device path (${tpm_default_path}) or mssim, sgx, swtpm/net url (mssim://localhost, sgx://localhost, net://localhost:1234) or 'dummy' for dummy TPM"`
	DummyTPM   bool     `name:"notpm" help:"Force using insecure dummy TPM if this device has no real TPM" default:"false"`
	Standalone bool     `help:"Don't connect to windows service to run enroll"`
}

func (enroll *enrollCmd) Run(agentCore *core.AttestationClient, stdLogOut *io.Writer) error {
	ctx := context.Background()

	runSvcClient := runtime.GOOS == "windows" && !enroll.Standalone

	var err error
	var client *ipc.Client
	if runSvcClient {
		client, _, err = ipc.ConnectNamedPipe(ctx, *stdLogOut)
		if err != nil {
			log.Error().Err(err).Msg("failed to connect to server")
			return err
		}
		defer client.Shutdown()

		args := ipc.CmdArgsEnroll{Token: enroll.Token, DummyTPM: enroll.DummyTPM, TPMPath: enroll.TPM, Server: enroll.Server}
		var reply *ipc.CmdArgsEnrollReply
		if reply, err = client.Enroll(args); err != nil {
			log.Error().Err(err).Msg("failed to enroll on remote server")
		} else if len(reply.Status) > 0 {
			err = core.AttestationClientError(reply.Status)
		}
	} else {
		// when server override is set during enroll store it in state
		// so OS startup scripts can attest without needing to know the server URL
		if enroll.Server != nil {
			agentCore.OverrideServerUrl(enroll.Server)
		}

		err = agentCore.Enroll(ctx, enroll.Token, enroll.DummyTPM, enroll.TPM)
	}

	if err != nil {
		core.LogEnrollErrors(&log.Logger, err)
		tui.SetUIState(tui.StEnrollFailed)
		return err
	}

	tui.SetUIState(tui.StEnrollSuccess)
	log.Info().Msg("Device enrolled")
	if enroll.NoAttest {
		log.Info().Msgf("You can now attest with \"%s attest\"", os.Args[0])
		return nil
	}

	if runSvcClient {
		var reply *ipc.CmdArgsAttestReply
		if reply, err = client.Attest(ipc.CmdArgsAttest{}); err != nil {
			log.Error().Err(err).Msg("failed to attest on remote server")
		} else if len(reply.Status) > 0 {
			err = core.AttestationClientError(reply.Status)
		}
	} else {
		_, err = agentCore.Attest(ctx, false)
	}

	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	return nil
}
