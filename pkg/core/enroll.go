package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func Enroll(ctx context.Context, glob *GlobalOptions, token string) error {
	tui.SetUIState(tui.StCreateKeys)
	log.Info("Creating Endorsement key")
	ekHandle, ekPub, err := glob.Anchor.GetEndorsementKey()
	if err != nil {
		log.Debugf("tcg.GetEndorsementKey(glob.TpmConn): %s", err.Error())
		log.Error("Cannot create Endorsement key")
		return err
	}
	defer ekHandle.Flush(glob.Anchor)
	glob.State.EndorsementKey = api.PublicKey(ekPub)

	log.Info("Reading Endorsement key certificate")
	ekCert, err := glob.Anchor.ReadEKCertificate()
	if err != nil {
		log.Debugf("tcg.ReadEKCertificate(glob.TpmConn): %s", err.Error())
		log.Warn("No Endorsement key certificate in NVRAM")
		glob.State.EndorsementCertificate = nil
	} else {
		c := api.Certificate(*ekCert)
		glob.State.EndorsementCertificate = &c
	}

	log.Info("Creating Root key")
	rootHandle, rootPub, err := glob.Anchor.CreateAndLoadRoot(glob.EndorsementAuth, "", &glob.State.Config.Root.Public)
	if err != nil {
		log.Debugf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		log.Error("Failed to create root key")
		return err
	}
	defer rootHandle.Flush(glob.Anchor)

	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		log.Debugf("Name(rootPub): %s", err)
		log.Error("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return err
	}
	glob.State.Root.Name = rootName

	keyCerts := make(map[string]api.Key)
	glob.State.Keys = make(map[string]state.DeviceKeyV3)
	for keyName, keyTmpl := range glob.State.Config.Keys {
		log.Infof("Creating '%s' key", keyName)
		keyAuth, err := tcg.GenerateAuthValue()
		if err != nil {
			log.Debugf("tcg.GenerateAuthValue(): %s", err.Error())
			log.Error("Failed to generate Auth Value")
			return err
		}
		key, priv, err := glob.Anchor.CreateAndCertifyDeviceKey(rootHandle, glob.State.Root.Auth, keyTmpl, keyAuth)
		if err != nil {
			log.Debugf("tcg.CreateAndCertifyDeviceKey(..): %s", err.Error())
			log.Errorf("Failed to create %s key and its certification values", keyName)
			return err
		}

		glob.State.Keys[keyName] = state.DeviceKeyV3{
			Public:     key.Public,
			Private:    priv,
			Auth:       keyAuth,
			Credential: "",
		}
		keyCerts[keyName] = key
	}

	log.Info("Certifying TPM keys")
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("Failed to get hostname")
		return err
	}

	cookie, err := api.Cookie(rand.Reader)
	if err != nil {
		log.Debugf("Failed to create secure cookie: %s", err)
		log.Error("Cannot access random number generator")
		return err
	}

	var enrollReq api.Enrollment = api.Enrollment{
		NameHint:               hostname,
		Cookie:                 cookie,
		EndoresmentCertificate: glob.State.EndorsementCertificate,
		EndoresmentKey:         glob.State.EndorsementKey,
		Root:                   rootPub,
		Keys:                   keyCerts,
	}

	tui.SetUIState(tui.StEnrollKeys)
	enrollResp, err := glob.Client.Enroll(ctx, token, enrollReq)
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		log.Error("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
		return err
	} else if errors.Is(err, api.FormatError) {
		log.Error("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
		return err
	} else if errors.Is(err, api.NetworkError) {
		log.Error("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return err
	} else if errors.Is(err, api.ServerError) {
		log.Error("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
		return err
	} else if errors.Is(err, api.PaymentError) {
		log.Error("Enrollment failed. A payment is required for further enrollments.")
		return err
	} else if err != nil {
		log.Error("Enrollment failed. An unknown error occured. Please try again later.")
		return err
	}

	if len(enrollResp) != len(enrollReq.Keys) {
		log.Debugf("No or missing credentials in server response")
		log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
		return fmt.Errorf("no credentials field")
	}

	keyCreds := make(map[string]string)
	for _, encCred := range enrollResp {
		key, ok := glob.State.Keys[encCred.Name]
		if !ok {
			log.Debugf("Got encrypted credential for unknown key %s", encCred.Name)
			log.Error("Enrollment failed. Cannot understand the servers response. Make sure the agent is up to date.")
			return fmt.Errorf("unknown key")
		}

		handle, err := glob.Anchor.LoadDeviceKey(rootHandle, glob.State.Root.Auth, key.Public, key.Private)
		if err != nil {
			log.Debugf("tcg.LoadDeviceKey(..): %s", err)
			log.Errorf("Cannot load %s key.", encCred.Name)
			return err
		}

		cred, err := glob.Anchor.ActivateDeviceKey(*encCred, glob.EndorsementAuth, key.Auth, handle, ekHandle, glob.State)
		handle.Flush(glob.Anchor)
		if err != nil {
			log.Debugf("tcg.ActivateDeviceKey(..): %s", err)
			log.Errorf("Cannot active %s key.", encCred.Name)
			return err
		}

		keyCreds[encCred.Name] = cred
	}

	if len(keyCreds) != len(glob.State.Keys) {
		log.Warnf("Failed to active all keys. Got credentials for %d keys but requested %d.", len(keyCreds), len(glob.State.Keys))

		if _, ok := keyCerts["aik"]; !ok {
			log.Errorf("Server refused to certify attestation key.")
			return fmt.Errorf("no aik credential")
		}
	}

	for keyName, keyCred := range keyCreds {
		key := glob.State.Keys[keyName]
		key.Credential = keyCred
		glob.State.Keys[keyName] = key
	}

	return nil
}
