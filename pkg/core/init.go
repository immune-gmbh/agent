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
	"github.com/sirupsen/logrus"
)

var (
	// this is set by the build environment
	releaseId string = "unknown"

	// defaults
	defaultServerURL       string = "https://api.immu.ne/v2"
	defaultEndorsementAuth string = ""
)

func NewCore() *Core {
	return &Core{
		ReleaseId:       &releaseId,
		EndorsementAuth: defaultEndorsementAuth,
	}
}

func (core *Core) OpenTPM() error {
	a, err := tcg.OpenTPM(core.State.TPM, core.State.StubState)
	if err != nil {
		logrus.Debugf("tcg.OpenTPM(glob.State.TPM, glob.State.StubState): %s", err.Error())
		logrus.Errorf("Cannot open TPM: %s", core.State.TPM)
		return err
	}

	core.Anchor = a
	return nil
}

// load and migrate on-disk state
func (core *Core) initState(stateDir string) error {
	// stateDir is either the OS-specific default or what we get from the CLI
	if stateDir == "" {
		logrus.Error("No state directory specified")
		return errors.New("state parameter empty")
	}

	// test if the state directory is writable
	{
		err := os.MkdirAll(stateDir, os.ModeDir|0750)
		if err != nil {
			logrus.Errorf("Can't create state directory, check permissions: %s", stateDir)
			return err
		}
		tmp := filepath.Join(stateDir, "testfile")
		fd, err := os.Create(tmp)
		if err != nil {
			logrus.Errorf("Can't write in state directory, check permissions: %s", stateDir)
			return err
		}
		fd.Close()
		os.Remove(tmp)
	}

	core.StatePath = path.Join(stateDir, "keys")

	// load and migrate state
	st, update, err := state.LoadState(core.StatePath)
	if errors.Is(err, state.ErrNotExist) {
		logrus.Info("No previous state found")
		core.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		logrus.Error("Cannot read state, no permissions")
		return err
	} else if err != nil {
		logrus.Debugf("state.LoadState(%s): %s", core.StatePath, err)
		return err
	} else {
		core.State = st
	}
	if update {
		logrus.Debugf("Migrating state file to newest version")
		if err := core.State.Store(core.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", core.StatePath, err)
			return err
		}
	}

	return nil
}

func (core *Core) initClient(CA string) error {
	var caCert *x509.Certificate
	if CA != "" {
		buf, err := os.ReadFile(CA)
		if err != nil {
			logrus.Errorf("Cannot read '%s': %s", CA, err.Error())
			return err
		}

		if pem, _ := pem.Decode(buf); pem != nil {
			buf = pem.Bytes
		}

		caCert, err = x509.ParseCertificate(buf)
		if err != nil {
			logrus.Errorf("CA certificate ill-formed: %s", err.Error())
			return err
		}
	}

	// use server URL in state, if any, with cmdline setting taking precedence
	var srv *url.URL
	if core.Server != nil {
		srv = core.Server
	} else if core.State != nil && core.State.ServerURL != nil {
		srv = core.State.ServerURL
	} else {
		var err error
		srv, err = url.Parse(defaultServerURL)
		if err != nil {
			logrus.Fatal("default server URL is invalid")
		}
	}

	core.Client = api.NewClient(srv, caCert, releaseId)
	return nil
}

// try to get a new configuration from server
func (core *Core) UpdateConfig() error {
	update, err := core.State.EnsureFresh(&core.Client)
	if err != nil {
		logrus.Debugf("Fetching fresh config: %s", err)
		logrus.Error("Failed to load configuration from server")
		return err
	}

	// store it on-disk
	if update {
		logrus.Debugf("Storing new config from server")
		if err := core.State.Store(core.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", core.StatePath, err)
			return err
		}
	}

	return nil
}

func (core *Core) Init(stateDir, CA string, server *url.URL) error {
	// store server URL override
	core.Server = server

	// load on-disk state
	if err := core.initState(stateDir); err != nil {
		logrus.Error("Cannot restore state")
		return err
	}

	// init API client
	if err := core.initClient(CA); err != nil {
		return err
	}

	return nil
}
