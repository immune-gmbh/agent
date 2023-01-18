package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	// this is set by the build environment
	releaseId string = "unknown"

	// defaults
	defaultServerURL       string = "https://api.immu.ne/v2"
	defaultEndorsementAuth string = ""
)

func NewCore() *AttestationClient {
	return &AttestationClient{
		ReleaseId:       &releaseId,
		EndorsementAuth: defaultEndorsementAuth,
	}
}

func (ac *AttestationClient) OpenTPM() error {
	a, err := tcg.OpenTPM(ac.State.TPM, ac.State.StubState)
	if err != nil {
		ac.Log.Debug().Msgf("tcg.OpenTPM(glob.State.TPM, glob.State.StubState): %s", err.Error())
		ac.Log.Error().Msgf("Cannot open TPM: %s", ac.State.TPM)
		return err
	}

	ac.Anchor = a
	return nil
}

// load and migrate on-disk state
func (ac *AttestationClient) initState(stateDir string) error {
	// stateDir is either the OS-specific default or what we get from the CLI
	if stateDir == "" {
		ac.Log.Error().Msg("No state directory specified")
		return errors.New("state parameter empty")
	}

	// test if the state directory is writable
	{
		err := os.MkdirAll(stateDir, os.ModeDir|0750)
		if err != nil {
			ac.Log.Error().Msgf("Can't create state directory, check permissions: %s", stateDir)
			return err
		}
		tmp := filepath.Join(stateDir, "testfile")
		fd, err := os.Create(tmp)
		if err != nil {
			ac.Log.Error().Msgf("Can't write in state directory, check permissions: %s", stateDir)
			return err
		}
		fd.Close()
		os.Remove(tmp)
	}

	ac.StatePath = path.Join(stateDir, "keys")

	// load and migrate state
	st, update, err := state.LoadState(ac.StatePath)
	if errors.Is(err, state.ErrNotExist) {
		ac.Log.Info().Msg("No previous state found")
		ac.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		ac.Log.Error().Msg("Cannot read state, no permissions")
		return err
	} else if err != nil {
		ac.Log.Debug().Msgf("state.LoadState(%s): %s", ac.StatePath, err)
		return err
	} else {
		ac.State = st
	}
	if update {
		ac.Log.Debug().Msgf("Migrating state file to newest version")
		if err := ac.State.Store(ac.StatePath); err != nil {
			ac.Log.Debug().Msgf("Store(%s): %s", ac.StatePath, err)
			return err
		}
	}

	return nil
}

func (ac *AttestationClient) initClient(CA string) error {
	var caCert *x509.Certificate
	if CA != "" {
		buf, err := os.ReadFile(CA)
		if err != nil {
			ac.Log.Error().Msgf("Cannot read '%s': %s", CA, err.Error())
			return err
		}

		if pem, _ := pem.Decode(buf); pem != nil {
			buf = pem.Bytes
		}

		caCert, err = x509.ParseCertificate(buf)
		if err != nil {
			ac.Log.Error().Msgf("CA certificate ill-formed: %s", err.Error())
			return err
		}
	}

	// use server URL in state, if any, with cmdline setting taking precedence
	var srv *url.URL
	if ac.Server != nil {
		srv = ac.Server
	} else if ac.State != nil && ac.State.ServerURL != nil {
		srv = ac.State.ServerURL
	} else {
		var err error
		srv, err = url.Parse(defaultServerURL)
		if err != nil {
			log.Debug().Msg("default server URL is invalid")
			return ErrApiUrl
		}
	}

	ac.Client = api.NewClient(srv, caCert, releaseId)
	return nil
}

// try to get a new configuration from server
func (ac *AttestationClient) UpdateConfig() error {
	update, err := ac.State.EnsureFresh(&ac.Client)
	if err != nil {
		ac.Log.Debug().Msgf("Fetching fresh config: %s", err)
		ac.Log.Error().Msg("Failed to load configuration from server")
		return err
	}

	// store it on-disk
	if update {
		ac.Log.Debug().Msgf("Storing new config from server")
		if err := ac.State.Store(ac.StatePath); err != nil {
			ac.Log.Debug().Msgf("Store(%s): %s", ac.StatePath, err)
			return err
		}
	}

	return nil
}

func (ac *AttestationClient) Init(stateDir, CA string, server *url.URL, logger *zerolog.Logger) error {
	// store server URL override
	ac.Server = server

	// load on-disk state
	if err := ac.initState(stateDir); err != nil {
		ac.Log.Error().Msg("Cannot restore state")
		return err
	}

	// init API client
	if err := ac.initClient(CA); err != nil {
		return err
	}

	ac.Log = logger

	return nil
}
