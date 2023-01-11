package core

import (
	"net/url"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
)

type GlobalOptions struct {
	// program info
	ReleaseId *string

	// on-disk state
	State     *state.State
	StatePath string

	// derived from cli opts
	Server          *url.URL
	Client          api.Client
	Anchor          tcg.TrustAnchor
	EndorsementAuth string
}
