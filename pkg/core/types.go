package core

import (
	"net/url"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/sirupsen/logrus"
)

type Core struct {
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
	Log *logrus.Logger
}
