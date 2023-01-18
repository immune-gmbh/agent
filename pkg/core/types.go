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
	ErrEncodeJson      = errors.New("json encoding")
	ErrReadPcr         = errors.New("read pcr")
	ErrRootKey         = errors.New("create or load root key")
	ErrAik             = errors.New("create or load aik")
	ErrQuote           = errors.New("tpm quote")
	ErrUnknown         = errors.New("internal error")
	ErrApiUrl          = errors.New("api url broken")
	ErrEndorsementKey  = errors.New("create or load EK")
	ErrEnroll          = errors.New("internal enrollment error")
	ErrApiResponse     = errors.New("unexpected api response")
	ErrOpenTrustAnchor = errors.New("open trust anchor")
	ErrStateDir        = errors.New("create or write state dir")
	ErrCaFile          = errors.New("read or parse CA file")
	ErrStateLoad       = errors.New("other state load error")
	ErrStateStore      = errors.New("other state store error")
	ErrUpdateConfig    = errors.New("fetch config from server")
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
