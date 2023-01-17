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

func (core *Core) Enroll(ctx context.Context, token string) error {
	tui.SetUIState(tui.StCreateKeys)
	core.Log.Info("Creating Endorsement key")
	ekHandle, ekPub, err := core.Anchor.GetEndorsementKey()
	if err != nil {
		core.Log.Debugf("tcg.GetEndorsementKey(glob.TpmConn): %s", err.Error())
		core.Log.Error("Cannot create Endorsement key")
		return err
	}
	defer ekHandle.Flush(core.Anchor)
	core.State.EndorsementKey = api.PublicKey(ekPub)

	core.Log.Info("Reading Endorsement key certificate")
	ekCert, err := core.Anchor.ReadEKCertificate()
	if err != nil {
		core.Log.Debugf("tcg.ReadEKCertificate(glob.TpmConn): %s", err.Error())
		core.Log.Warn("No Endorsement key certificate in NVRAM")
		core.State.EndorsementCertificate = nil
	} else {
		c := api.Certificate(*ekCert)
		core.State.EndorsementCertificate = &c
	}

	core.Log.Info("Creating Root key")
	rootHandle, rootPub, err := core.Anchor.CreateAndLoadRoot(core.EndorsementAuth, "", &core.State.Config.Root.Public)
	if err != nil {
		core.Log.Debugf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		core.Log.Error("Failed to create root key")
		return err
	}
	defer rootHandle.Flush(core.Anchor)

	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		core.Log.Debugf("Name(rootPub): %s", err)
		core.Log.Error("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return err
	}
	core.State.Root.Name = rootName

	keyCerts := make(map[string]api.Key)
	core.State.Keys = make(map[string]state.DeviceKeyV3)
	for keyName, keyTmpl := range core.State.Config.Keys {
		core.Log.Infof("Creating '%s' key", keyName)
		keyAuth, err := tcg.GenerateAuthValue()
		if err != nil {
			core.Log.Debugf("tcg.GenerateAuthValue(): %s", err.Error())
			core.Log.Error("Failed to generate Auth Value")
			return err
		}
		key, priv, err := core.Anchor.CreateAndCertifyDeviceKey(rootHandle, core.State.Root.Auth, keyTmpl, keyAuth)
		if err != nil {
			core.Log.Debugf("tcg.CreateAndCertifyDeviceKey(..): %s", err.Error())
			core.Log.Errorf("Failed to create %s key and its certification values", keyName)
			return err
		}

		core.State.Keys[keyName] = state.DeviceKeyV3{
			Public:     key.Public,
			Private:    priv,
			Auth:       keyAuth,
			Credential: "",
		}
		keyCerts[keyName] = key
	}

	core.Log.Info("Certifying TPM keys")
	hostname, err := os.Hostname()
	if err != nil {
		core.Log.Errorf("Failed to get hostname")
		return err
	}

	cookie, err := api.Cookie(rand.Reader)
	if err != nil {
		core.Log.Debugf("Failed to create secure cookie: %s", err)
		core.Log.Error("Cannot access random number generator")
		return err
	}

	var enrollReq api.Enrollment = api.Enrollment{
		NameHint:               hostname,
		Cookie:                 cookie,
		EndoresmentCertificate: core.State.EndorsementCertificate,
		EndoresmentKey:         core.State.EndorsementKey,
		Root:                   rootPub,
		Keys:                   keyCerts,
	}

	tui.SetUIState(tui.StEnrollKeys)
	enrollResp, err := core.Client.Enroll(ctx, token, enrollReq)
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		core.Log.Error("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
		return err
	} else if errors.Is(err, api.FormatError) {
		core.Log.Error("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
		return err
	} else if errors.Is(err, api.NetworkError) {
		core.Log.Error("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return err
	} else if errors.Is(err, api.ServerError) {
		core.Log.Error("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
		return err
	} else if errors.Is(err, api.PaymentError) {
		core.Log.Error("Enrollment failed. A payment is required for further enrollments.")
		return err
	} else if err != nil {
		core.Log.Error("Enrollment failed. An unknown error occured. Please try again later.")
		return err
	}

	if len(enrollResp) != len(enrollReq.Keys) {
		core.Log.Debugf("No or missing credentials in server response")
		core.Log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
		return fmt.Errorf("no credentials field")
	}

	keyCreds := make(map[string]string)
	for _, encCred := range enrollResp {
		key, ok := core.State.Keys[encCred.Name]
		if !ok {
			core.Log.Debugf("Got encrypted credential for unknown key %s", encCred.Name)
			core.Log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
			return fmt.Errorf("unknown key")
		}

		handle, err := core.Anchor.LoadDeviceKey(rootHandle, core.State.Root.Auth, key.Public, key.Private)
		if err != nil {
			core.Log.Debugf("tcg.LoadDeviceKey(..): %s", err)
			core.Log.Errorf("Cannot load %s key.", encCred.Name)
			return err
		}

		cred, err := core.Anchor.ActivateDeviceKey(*encCred, core.EndorsementAuth, key.Auth, handle, ekHandle, core.State)
		handle.Flush(core.Anchor)
		if err != nil {
			core.Log.Debugf("tcg.ActivateDeviceKey(..): %s", err)
			core.Log.Errorf("Cannot active %s key.", encCred.Name)
			return err
		}

		keyCreds[encCred.Name] = cred
	}

	if len(keyCreds) != len(core.State.Keys) {
		core.Log.Warnf("Failed to active all keys. Got credentials for %d keys but requested %d.", len(keyCreds), len(core.State.Keys))

		if _, ok := keyCerts["aik"]; !ok {
			core.Log.Errorf("Server refused to certify attestation key.")
			return fmt.Errorf("no aik credential")
		}
	}

	for keyName, keyCred := range keyCreds {
		key := core.State.Keys[keyName]
		key.Credential = keyCred
		core.State.Keys[keyName] = key
	}

	return nil
}
