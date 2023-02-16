package core

import (
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/must"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/rs/zerolog"
)

var (
	// this is set by the build environment
	releaseId string = "unknown"

	// defaults
	defaultServerURL       *url.URL = must.Get(url.Parse("https://api.immune.app/v2"))
	defaultEndorsementAuth string   = ""
)

func NewCore() *AttestationClient {
	return &AttestationClient{
		ReleaseId:       &releaseId,
		EndorsementAuth: defaultEndorsementAuth,
	}
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

func (ac *AttestationClient) getServerUrl() *url.URL {
	// use server URL in state, if any
	if ac.State != nil && ac.State.ServerURL != nil {
		return ac.State.ServerURL
	} else {
		return defaultServerURL
	}
}

// try to get a new configuration from server
func (ac *AttestationClient) updateConfig() error {
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

func (ac *AttestationClient) Init(stateDir string, logger *zerolog.Logger) error {
	ac.Log = logger

	// load on-disk state
	if err := ac.initState(stateDir); err != nil {
		return err
	}

	// init API client
	ac.Client = api.NewClient(ac.getServerUrl(), nil, releaseId)

	return nil
}

// OverrideServerUrl sets URL in state re-inits the API client
// the changed URL becomes permanent when the state is stored, which happens during enroll and possibly when updating config
func (ac *AttestationClient) OverrideServerUrl(server *url.URL) {
	// store URL in state
	ac.State.ServerURL = server
	// re-init API client
	ac.Client = api.NewClient(ac.getServerUrl(), nil, releaseId)
}
