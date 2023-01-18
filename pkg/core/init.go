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
		ac.Log.Debug().Err(err).Msg("tcg.OpenTPM(glob.State.TPM, glob.State.StubState)")
		return ErrOpenTrustAnchor
	}

	ac.Anchor = a
	return nil
}

// load and migrate on-disk state
func (ac *AttestationClient) initState(stateDir string) error {
	// stateDir is either the OS-specific default or what we get from the CLI
	if stateDir == "" {
		ac.Log.Debug().Msg("no state directory specified")
		return ErrStateDir
	}

	// test if the state directory is writable
	{
		err := os.MkdirAll(stateDir, os.ModeDir|0750)
		if err != nil {
			return ErrStateDir
		}
		tmp := filepath.Join(stateDir, "testfile")
		fd, err := os.Create(tmp)
		if err != nil {
			return ErrStateDir
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
		return err
	} else if err != nil {
		ac.Log.Debug().Err(err).Msgf("state.LoadState(%s)", ac.StatePath)
		return ErrStateLoad
	} else {
		ac.State = st
	}

	if update {
		ac.Log.Info().Msg("Migrating state file to newest version")
		if err := ac.State.Store(ac.StatePath); err != nil {
			ac.Log.Debug().Err(err).Msgf("State.Store(%s)", ac.StatePath)
			return ErrStateStore
		}
	}

	return nil
}

func (ac *AttestationClient) initClient(CA string) error {
	var caCert *x509.Certificate
	if CA != "" {
		buf, err := os.ReadFile(CA)
		if err != nil {
			ac.Log.Debug().Err(err).Msgf("Cannot read: %s", CA)
			return ErrCaFile
		}

		if pem, _ := pem.Decode(buf); pem != nil {
			buf = pem.Bytes
		}

		caCert, err = x509.ParseCertificate(buf)
		if err != nil {
			ac.Log.Debug().Err(err).Msgf("CA certificate ill-formed")
			return ErrCaFile
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
		ac.Log.Debug().Err(err).Msg("fetching fresh config")
		return ErrUpdateConfig
	}

	// store it on-disk
	if update {
		ac.Log.Info().Msg("Storing new config from server")
		if err := ac.State.Store(ac.StatePath); err != nil {
			ac.Log.Debug().Err(err).Msgf("State.Store(%s)", ac.StatePath)
			return ErrStateStore
		}
	}

	return nil
}

func (ac *AttestationClient) Init(stateDir, CA string, server *url.URL, logger *zerolog.Logger) error {
	// store server URL override
	ac.Server = server

	// load on-disk state
	if err := ac.initState(stateDir); err != nil {
		return err
	}

	// init API client
	if err := ac.initClient(CA); err != nil {
		return err
	}

	ac.Log = logger

	return nil
}
