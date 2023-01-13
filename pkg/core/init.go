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

func OpenTPM(glob *Core) error {
	a, err := tcg.OpenTPM(glob.State.TPM, glob.State.StubState)
	if err != nil {
		logrus.Debugf("tcg.OpenTPM(glob.State.TPM, glob.State.StubState): %s", err.Error())
		logrus.Errorf("Cannot open TPM: %s", glob.State.TPM)
		return err
	}

	glob.Anchor = a
	return nil
}

func NewGlobalOptions() *Core {
	return &Core{
		ReleaseId:       &releaseId,
		EndorsementAuth: defaultEndorsementAuth,
	}
}

// load and migrate on-disk state
func initState(glob *Core, stateDir string) error {
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

	glob.StatePath = path.Join(stateDir, "keys")

	// load and migrate state
	st, update, err := state.LoadState(glob.StatePath)
	if errors.Is(err, state.ErrNotExist) {
		logrus.Info("No previous state found")
		glob.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		logrus.Error("Cannot read state, no permissions")
		return err
	} else if err != nil {
		logrus.Debugf("state.LoadState(%s): %s", glob.StatePath, err)
		return err
	} else {
		glob.State = st
	}
	if update {
		logrus.Debugf("Migrating state file to newest version")
		if err := glob.State.Store(glob.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", glob.StatePath, err)
			return err
		}
	}

	return nil
}

func initClient(glob *Core, CA string) error {
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
	if glob.Server != nil {
		srv = glob.Server
	} else if glob.State != nil && glob.State.ServerURL != nil {
		srv = glob.State.ServerURL
	} else {
		var err error
		srv, err = url.Parse(defaultServerURL)
		if err != nil {
			logrus.Fatal("default server URL is invalid")
		}
	}

	glob.Client = api.NewClient(srv, caCert, releaseId)
	return nil
}

// try to get a new configuration from server
func UpdateConfig(glob *Core) error {
	update, err := glob.State.EnsureFresh(&glob.Client)
	if err != nil {
		logrus.Debugf("Fetching fresh config: %s", err)
		logrus.Error("Failed to load configuration from server")
		return err
	}

	// store it on-disk
	if update {
		logrus.Debugf("Storing new config from server")
		if err := glob.State.Store(glob.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", glob.StatePath, err)
			return err
		}
	}

	return nil
}

func Init(glob *Core, stateDir, CA string, server *url.URL) error {
	// store server URL override
	glob.Server = server

	// load on-disk state
	if err := initState(glob, stateDir); err != nil {
		logrus.Error("Cannot restore state")
		return err
	}

	// init API client
	if err := initClient(glob, CA); err != nil {
		return err
	}

	return nil
}
