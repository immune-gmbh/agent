package core

import (
	"errors"
	"net/url"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/rs/zerolog"
)

var (
	ErrEncodeJson = errors.New("Internal error while encoding firmware state")
	ErrReadPcr    = errors.New("Failed to read all PCR values")
	ErrRootKey    = errors.New("")
	ErrAik        = errors.New("")
	ErrQuote      = errors.New("")
	ErrUnknown    = errors.New("")
	ErrApiUrl     = errors.New("")
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
	Anchor          tcg.TrustAnchor
	EndorsementAuth string

	// Logging
	Log *zerolog.Logger
}
