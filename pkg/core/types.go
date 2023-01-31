package core

import (
	"net/url"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/rs/zerolog"
)

type AttestationClient struct {
	// program info
	ReleaseId *string

	// on-disk state
	State     *state.State
	StatePath string

	// API client
	Server *url.URL
	Client api.Client

	// TPM
	EndorsementAuth string

	// Logging
	Log *zerolog.Logger
}
