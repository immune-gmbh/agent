package cli

import (
	"context"
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/sirupsen/logrus"
)

type enrollCmd struct {
	NoAttest bool   `help:"Don't attest after successful enrollment" default:"false"`
	Token    string `arg:"" required:"" name:"token" help:"Enrollment authentication token"`
	Name     string `arg:"" optional:"" name:"name hint" help:"Name to assign to the device. May get suffixed by a counter if already taken. Defaults to the hostname."`
	TPM      string `name:"tpm" default:"${tpm_default_path}" help:"TPM device: device path (${tpm_default_path}) or mssim, sgx, swtpm/net url (mssim://localhost, sgx://localhost, net://localhost:1234) or 'dummy' for dummy TPM"`
	DummyTPM bool   `name:"notpm" help:"Force using insecure dummy TPM if this device has no real TPM" default:"false"`
}

func (enroll *enrollCmd) Run(agentCore *core.Core) error {
	ctx := context.Background()

	// store used TPM in state, use dummy TPM only if forced
	if enroll.DummyTPM {
		agentCore.State.TPM = state.DummyTPMIdentifier
	} else {
		agentCore.State.TPM = enroll.TPM
	}

	if err := core.OpenTPM(agentCore); err != nil {
		if agentCore.State.TPM != state.DummyTPMIdentifier {
			tui.SetUIState(tui.StSelectTAFailed)
		}
		return err
	}
	tui.SetUIState(tui.StSelectTASuccess)

	// when server is set on cmdline during enroll store it in state
	// so OS startup scripts can attest without needing to know the server URL
	if agentCore.Server != nil {
		agentCore.State.ServerURL = agentCore.Server
	}

	if err := agentCore.Enroll(ctx, enroll.Token); err != nil {
		tui.SetUIState(tui.StEnrollFailed)
		return err
	}

	// incorporate dummy TPM state
	if stub, ok := agentCore.Anchor.(*tcg.SoftwareAnchor); ok {
		if st, err := stub.Store(); err != nil {
			logrus.Debugf("SoftwareAnchor.Store: %s", err)
			logrus.Errorf("Failed to save stub TPM state to disk")
		} else {
			agentCore.State.StubState = st
		}
	}

	// save the new state to disk
	if err := agentCore.State.Store(agentCore.StatePath); err != nil {
		logrus.Debugf("Store(%s): %s", agentCore.StatePath, err)
		logrus.Errorf("Failed to save activated keys to disk")
		return err
	}

	tui.SetUIState(tui.StEnrollSuccess)
	logrus.Infof("Device enrolled")
	if enroll.NoAttest {
		logrus.Infof("You can now attest with \"%s attest\"", os.Args[0])
		return nil
	}

	return doAttest(agentCore, ctx, "", false)
}
