package core

import (
	"context"
	"crypto/rand"
	"errors"
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func (ac *AttestationClient) Enroll(ctx context.Context, token string, dummyTPM bool, tpmPath string) error {
	// store used TPM in state, use dummy TPM only if forced
	if dummyTPM {
		ac.State.TPM = state.DummyTPMIdentifier
	} else {
		ac.State.TPM = tpmPath
	}

	a, err := tcg.OpenTPM(ac.State.TPM, ac.State.StubState)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.OpenTPM(glob.State.TPM, glob.State.StubState)")

		// XXX we should properly map errors of supporting packages to attestation client error codes in the future
		// XXX and we need more errors instead of just returning ErrOpenTrustAnchor; in tui mode the info message won't be visible
		if errors.Is(err, tcg.ErrTpmV12Unsupported) {
			ac.Log.Info().Msg("Unsupported TPM version 1.2. Please contact us via sales@immu.ne.")
		} else if errors.Is(err, tcg.ErrTpmSelectionInvalid) {
			ac.Log.Info().Msg("The TPM selection is invalid")
		}

		// don't show tpm step in tui when we don't use a tpm
		if ac.State.TPM != state.DummyTPMIdentifier {
			tui.SetUIState(tui.StSelectTAFailed)
		}

		return ErrOpenTrustAnchor
	}
	defer a.Close()
	tui.SetUIState(tui.StSelectTASuccess)

	// when server override is set during enroll store it in state
	// so OS startup scripts can attest without needing to know the server URL
	if ac.Server != nil {
		ac.State.ServerURL = ac.Server
	}

	tui.SetUIState(tui.StCreateKeys)
	ac.Log.Info().Msg("Creating Endorsement key")
	ekHandle, ekPub, err := a.GetEndorsementKey()
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.GetEndorsementKey(glob.TpmConn)")
		return ErrEndorsementKey
	}
	defer ekHandle.Flush(a)
	ac.State.EndorsementKey = api.PublicKey(ekPub)

	ac.Log.Info().Msg("Reading Endorsement key certificate")
	ekCert, err := a.ReadEKCertificate()
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.ReadEKCertificate(glob.TpmConn)")
		ac.Log.Warn().Msg("No Endorsement key certificate in NVRAM")
		ac.State.EndorsementCertificate = nil
	} else {
		c := api.Certificate(*ekCert)
		ac.State.EndorsementCertificate = &c
	}

	ac.Log.Info().Msg("Creating Root key")
	rootHandle, rootPub, err := a.CreateAndLoadRoot(ac.EndorsementAuth, "", &ac.State.Config.Root.Public)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.CreateAndLoadRoot(..)")
		return ErrRootKey
	}
	defer rootHandle.Flush(a)

	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("Name(rootPub)")
		return ErrRootKey
	}
	ac.State.Root.Name = rootName

	keyCerts := make(map[string]api.Key)
	ac.State.Keys = make(map[string]state.DeviceKeyV3)
	for keyName, keyTmpl := range ac.State.Config.Keys {
		ac.Log.Info().Msgf("Creating '%s' key", keyName)
		keyAuth, err := tcg.GenerateAuthValue()
		if err != nil {
			ac.Log.Debug().Err(err).Msg("tcg.GenerateAuthValue()")
			return ErrEnroll
		}
		key, priv, err := a.CreateAndCertifyDeviceKey(rootHandle, ac.State.Root.Auth, keyTmpl, keyAuth)
		if err != nil {
			ac.Log.Debug().Err(err).Msgf("tcg.CreateAndCertifyDeviceKey(..): %s", keyName)
			return ErrEnroll
		}

		ac.State.Keys[keyName] = state.DeviceKeyV3{
			Public:     key.Public,
			Private:    priv,
			Auth:       keyAuth,
			Credential: "",
		}
		keyCerts[keyName] = key
	}

	ac.Log.Info().Msg("Certifying TPM keys")
	hostname, err := os.Hostname()
	if err != nil {
		ac.Log.Debug().Err(err).Msg("failed to get hostname")
		return ErrEnroll
	}

	cookie, err := api.Cookie(rand.Reader)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("failed to create secure cookie")
		return ErrEnroll
	}

	var enrollReq api.Enrollment = api.Enrollment{
		NameHint:               hostname,
		Cookie:                 cookie,
		EndoresmentCertificate: ac.State.EndorsementCertificate,
		EndoresmentKey:         ac.State.EndorsementKey,
		Root:                   rootPub,
		Keys:                   keyCerts,
	}

	tui.SetUIState(tui.StEnrollKeys)
	enrollResp, err := ac.Client.Enroll(ctx, token, enrollReq)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("client.Enroll(..)")

		// pass-through API errors and replace all others with ErrUnknown
		if !(errors.Is(err, api.AuthError) ||
			errors.Is(err, api.FormatError) ||
			errors.Is(err, api.NetworkError) ||
			errors.Is(err, api.ServerError) ||
			errors.Is(err, api.PaymentError)) {
			err = ErrUnknown
		}

		return err
	}

	if len(enrollResp) != len(enrollReq.Keys) {
		ac.Log.Debug().Msg("No or missing credentials in server response")
		return ErrApiResponse
	}

	keyCreds := make(map[string]string)
	for _, encCred := range enrollResp {
		key, ok := ac.State.Keys[encCred.Name]
		if !ok {
			ac.Log.Debug().Msgf("Got encrypted credential for unknown key %s", encCred.Name)
			return ErrApiResponse
		}

		handle, err := a.LoadDeviceKey(rootHandle, ac.State.Root.Auth, key.Public, key.Private)
		if err != nil {
			ac.Log.Debug().Err(err).Msgf("tcg.LoadDeviceKey(..): %s", encCred.Name)
			return ErrEnroll
		}

		cred, err := a.ActivateDeviceKey(*encCred, ac.EndorsementAuth, key.Auth, handle, ekHandle, ac.State)
		handle.Flush(a)
		if err != nil {
			ac.Log.Debug().Err(err).Msgf("tcg.ActivateDeviceKey(..): %s", encCred.Name)
			return ErrEnroll
		}

		keyCreds[encCred.Name] = cred
	}

	if len(keyCreds) != len(ac.State.Keys) {
		ac.Log.Warn().Msgf("Failed to active all keys. Got credentials for %d keys but requested %d.", len(keyCreds), len(ac.State.Keys))

		if _, ok := keyCerts["aik"]; !ok {
			return ErrAik
		}
	}

	for keyName, keyCred := range keyCreds {
		key := ac.State.Keys[keyName]
		key.Credential = keyCred
		ac.State.Keys[keyName] = key
	}

	// incorporate dummy TPM state
	if stub, ok := a.(*tcg.SoftwareAnchor); ok {
		if st, err := stub.Store(); err != nil {
			ac.Log.Debug().Err(err).Msg("SoftwareAnchor.Store")
			return ErrStateStore
		} else {
			ac.State.StubState = st
		}
	}

	// save the new state to disk
	if err := ac.State.Store(ac.StatePath); err != nil {
		ac.Log.Debug().Err(err).Msgf("State.Store(%s)", ac.StatePath)
		return ErrStateStore
	}

	return nil
}
