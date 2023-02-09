package cli

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/rs/zerolog/log"
)

type enrollCmd struct {
	Server   *url.URL `name:"server" help:"immune SaaS API URL" type:"*url.URL"`
	NoAttest bool     `help:"Don't attest after successful enrollment" default:"false"`
	Token    string   `arg:"" required:"" name:"token" help:"Enrollment authentication token"`
	Name     string   `arg:"" optional:"" name:"name hint" help:"Name to assign to the device. May get suffixed by a counter if already taken. Defaults to the hostname."`
	TPM      string   `name:"tpm" default:"${tpm_default_path}" help:"TPM device: device path (${tpm_default_path}) or mssim, sgx, swtpm/net url (mssim://localhost, sgx://localhost, net://localhost:1234) or 'dummy' for dummy TPM"`
	DummyTPM bool     `name:"notpm" help:"Force using insecure dummy TPM if this device has no real TPM" default:"false"`
}

func (enroll *enrollCmd) Run(agentCore *core.AttestationClient) error {
	ctx := context.Background()

	// when server override is set during enroll store it in state
	// so OS startup scripts can attest without needing to know the server URL
	if enroll.Server != nil {
		agentCore.OverrideServerUrl(enroll.Server)
	}

	if err := agentCore.Enroll(ctx, enroll.Token, enroll.DummyTPM, enroll.TPM); err != nil {
		if errors.Is(err, api.AuthError) {
			log.Error().Msg("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
		} else if errors.Is(err, api.FormatError) {
			log.Error().Msg("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
		} else if errors.Is(err, api.NetworkError) {
			log.Error().Msg("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		} else if errors.Is(err, api.ServerError) {
			log.Error().Msg("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
		} else if errors.Is(err, api.PaymentError) {
			log.Error().Msg("Enrollment failed. A payment is required for further enrollments.")
		} else if errors.Is(err, core.ErrRootKey) {
			log.Error().Msg("Failed to create or load root key.")
		} else if errors.Is(err, core.ErrAik) {
			log.Error().Msg("Server refused to certify attestation key.")
		} else if errors.Is(err, core.ErrEndorsementKey) {
			log.Error().Msg("Cannot create Endorsement key.")
		} else if errors.Is(err, core.ErrEnroll) {
			log.Error().Msg("Internal error during enrollment.")
		} else if errors.Is(err, core.ErrApiResponse) {
			log.Error().Msg("Server resonse not understood. Is your agent up-to-date?")
		} else if errors.Is(err, core.ErrStateStore) {
			log.Error().Msg("Failed to store state.")
		} else if errors.Is(err, core.ErrOpenTrustAnchor) {
			log.Error().Msg("Cannot open TPM")
		} else if errors.Is(err, core.ErrUpdateConfig) {
			log.Error().Msg("Failed to load configuration from server")
		} else if err != nil {
			log.Error().Msg("Enrollment failed. An unknown error occured. Please try again later.")
		}

		tui.SetUIState(tui.StEnrollFailed)
		return err
	}

	tui.SetUIState(tui.StEnrollSuccess)
	log.Info().Msg("Device enrolled")
	if enroll.NoAttest {
		log.Info().Msgf("You can now attest with \"%s attest\"", os.Args[0])
		return nil
	}

	_, err := agentCore.Attest(ctx, false)
	if err != nil {
		core.LogAttestErrors(&log.Logger, err)
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	return nil
}
