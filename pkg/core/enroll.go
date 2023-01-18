package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func (ac *AttestationClient) Enroll(ctx context.Context, token string) error {
	tui.SetUIState(tui.StCreateKeys)
	ac.Log.Info().Msg("Creating Endorsement key")
	ekHandle, ekPub, err := ac.Anchor.GetEndorsementKey()
	if err != nil {
		ac.Log.Debug().Msgf("tcg.GetEndorsementKey(glob.TpmConn): %s", err.Error())
		ac.Log.Error().Msg("Cannot create Endorsement key")
		return err
	}
	defer ekHandle.Flush(ac.Anchor)
	ac.State.EndorsementKey = api.PublicKey(ekPub)

	ac.Log.Info().Msg("Reading Endorsement key certificate")
	ekCert, err := ac.Anchor.ReadEKCertificate()
	if err != nil {
		ac.Log.Debug().Msgf("tcg.ReadEKCertificate(glob.TpmConn): %s", err.Error())
		ac.Log.Warn().Msg("No Endorsement key certificate in NVRAM")
		ac.State.EndorsementCertificate = nil
	} else {
		c := api.Certificate(*ekCert)
		ac.State.EndorsementCertificate = &c
	}

	ac.Log.Info().Msg("Creating Root key")
	rootHandle, rootPub, err := ac.Anchor.CreateAndLoadRoot(ac.EndorsementAuth, "", &ac.State.Config.Root.Public)
	if err != nil {
		ac.Log.Debug().Msgf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		ac.Log.Error().Msg("Failed to create root key")
		return err
	}
	defer rootHandle.Flush(ac.Anchor)

	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		ac.Log.Debug().Msgf("Name(rootPub): %s", err)
		ac.Log.Error().Msg("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return err
	}
	ac.State.Root.Name = rootName

	keyCerts := make(map[string]api.Key)
	ac.State.Keys = make(map[string]state.DeviceKeyV3)
	for keyName, keyTmpl := range ac.State.Config.Keys {
		ac.Log.Info().Msgf("Creating '%s' key", keyName)
		keyAuth, err := tcg.GenerateAuthValue()
		if err != nil {
			ac.Log.Debug().Msgf("tcg.GenerateAuthValue(): %s", err.Error())
			ac.Log.Error().Msg("Failed to generate Auth Value")
			return err
		}
		key, priv, err := ac.Anchor.CreateAndCertifyDeviceKey(rootHandle, ac.State.Root.Auth, keyTmpl, keyAuth)
		if err != nil {
			ac.Log.Debug().Msgf("tcg.CreateAndCertifyDeviceKey(..): %s", err.Error())
			ac.Log.Error().Msgf("Failed to create %s key and its certification values", keyName)
			return err
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
		ac.Log.Error().Msgf("Failed to get hostname")
		return err
	}

	cookie, err := api.Cookie(rand.Reader)
	if err != nil {
		ac.Log.Debug().Msgf("Failed to create secure cookie: %s", err)
		ac.Log.Error().Msg("Cannot access random number generator")
		return err
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
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		ac.Log.Error().Msg("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
		return err
	} else if errors.Is(err, api.FormatError) {
		ac.Log.Error().Msg("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
		return err
	} else if errors.Is(err, api.NetworkError) {
		ac.Log.Error().Msg("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return err
	} else if errors.Is(err, api.ServerError) {
		ac.Log.Error().Msg("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
		return err
	} else if errors.Is(err, api.PaymentError) {
		ac.Log.Error().Msg("Enrollment failed. A payment is required for further enrollments.")
		return err
	} else if err != nil {
		ac.Log.Error().Msg("Enrollment failed. An unknown error occured. Please try again later.")
		return err
	}

	if len(enrollResp) != len(enrollReq.Keys) {
		ac.Log.Debug().Msgf("No or missing credentials in server response")
		ac.Log.Error().Msg("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
		return fmt.Errorf("no credentials field")
	}

	keyCreds := make(map[string]string)
	for _, encCred := range enrollResp {
		key, ok := ac.State.Keys[encCred.Name]
		if !ok {
			ac.Log.Debug().Msgf("Got encrypted credential for unknown key %s", encCred.Name)
			ac.Log.Error().Msg("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
			return fmt.Errorf("unknown key")
		}

		handle, err := ac.Anchor.LoadDeviceKey(rootHandle, ac.State.Root.Auth, key.Public, key.Private)
		if err != nil {
			ac.Log.Debug().Msgf("tcg.LoadDeviceKey(..): %s", err)
			ac.Log.Error().Msgf("Cannot load %s key.", encCred.Name)
			return err
		}

		cred, err := ac.Anchor.ActivateDeviceKey(*encCred, ac.EndorsementAuth, key.Auth, handle, ekHandle, ac.State)
		handle.Flush(ac.Anchor)
		if err != nil {
			ac.Log.Debug().Msgf("tcg.ActivateDeviceKey(..): %s", err)
			ac.Log.Error().Msgf("Cannot active %s key.", encCred.Name)
			return err
		}

		keyCreds[encCred.Name] = cred
	}

	if len(keyCreds) != len(ac.State.Keys) {
		ac.Log.Warn().Msgf("Failed to active all keys. Got credentials for %d keys but requested %d.", len(keyCreds), len(ac.State.Keys))

		if _, ok := keyCerts["aik"]; !ok {
			ac.Log.Error().Msgf("Server refused to certify attestation key.")
			return fmt.Errorf("no aik credential")
		}
	}

	for keyName, keyCred := range keyCreds {
		key := ac.State.Keys[keyName]
		key.Credential = keyCred
		ac.State.Keys[keyName] = key
	}

	return nil
}
