package state

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
)

const (
	ClientStateTypeV2 = "client-state/2"
	ClientStateTypeV3 = "client-state/3"
	ClientStateType   = ClientStateTypeV3

	// DefaultVendorSubdir is the name of the subdirectory we create in various common locations (f.e. /var, /etc) to store our data
	// note: if you change this name, you also have to modify the reference in the windows installer wix main xml file
	DefaultVendorSubdir string = "immune-guard"

	DummyTPMIdentifier string = "dummy"
)

var (
	ErrNotExist = errors.New("non existent")
	ErrInvalid  = errors.New("invalid data")
	ErrNoPerm   = errors.New("no permissions")
)

// Current "head" state struct definition
type State StateV3
type DeviceKey DeviceKeyV3

// returns true if a new config was fetched
// this is not really a responsibility of the state at all, however it'll
// remain here for the time being. just don't make this depend on specific
// state versions, as the config structure is from the public API and thus
// has its own versioning and there should be separate code handling
// different API versions.
func (s *State) EnsureFresh(cl *api.Client) (bool, error) {
	ctx := context.Background()
	now := time.Now()

	cfg, err := cl.Configuration(ctx, &s.LastUpdate)
	if err != nil {
		return false, err
	}

	// if cfg is nil then there is no new config and we should use a cached version
	if cfg != nil {
		s.Config = *cfg
		update := s.LastUpdate != time.Time{}
		s.LastUpdate = now

		return update, nil
	}

	return false, nil
}

// LoadState returns a loaded state and a bool if it has been updated or error
func LoadState(keysPath string) (*State, bool, error) {
	logrus.Traceln("load on-disk state")
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		return nil, false, ErrNotExist
	} else if os.IsPermission(err) {
		return nil, false, ErrNoPerm
	} else if err != nil {
		return nil, false, err
	}

	file, err := ioutil.ReadFile(keysPath)
	if err != nil {
		return nil, false, err
	}

	return migrateState(file)
}

// returns true when there was no tpm selection before
func selectTPM(st *State) bool {
	// if our state does not contain a TPM path do a best-effort default selection
	if st.TPM == "" {
		if st.StubState != nil {
			st.TPM = DummyTPMIdentifier
		} else {
			st.TPM = DefaultTPMDevice()
		}
		return true
	}

	return false
}

// the bool is true when the state has been updated
func migrateState(raw []byte) (*State, bool, error) {
	var dict map[string]interface{}

	if err := json.Unmarshal(raw, &dict); err != nil {
		logrus.Debugf("State file is not a JSON dict: %s", err)
		return nil, false, ErrInvalid
	}

	if val, ok := dict["type"]; ok {
		if str, ok := val.(string); ok {
			switch str {
			case ClientStateTypeV2:
				logrus.Debugf("Migrating state from v2 to v3")
				if st3, err := migrateStateV2(raw); err != nil {
					return nil, false, err
				} else {
					st := State(*st3)
					selectTPM(&st)
					return &st, true, err
				}
			case ClientStateTypeV3:
				var st State
				err := json.Unmarshal(raw, &st)
				update := selectTPM(&st)
				return &st, update, err
			default:
				logrus.Debugf("Unknown state type '%s'", str)
				return nil, false, ErrInvalid
			}
		} else {
			logrus.Debugf("State file type is not a string")
		}
	} else {
		logrus.Debugf("State file has no type")
	}

	return nil, false, ErrInvalid
}

func (st *State) Store(keysPath string) error {
	str, err := json.Marshal(*st)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(keysPath), 0755)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(keysPath, str, 0600)
}

func NewState() *State {
	return (*State)(newStateV3())
}

func (s *State) IsEnrolled() bool {
	return (*StateV3)(s).IsEnrolled()
}
