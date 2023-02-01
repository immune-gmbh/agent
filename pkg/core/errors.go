package core

import (
	"errors"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
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
	ErrStateLoad       = errors.New("other state load error")
	ErrStateStore      = errors.New("other state store error")
	ErrUpdateConfig    = errors.New("fetch config from server")
)

// XXX these log functions are more part of tui package

// LogAttestErrors is a helper function to translate errors to text and log them directly
func LogAttestErrors(l *zerolog.Logger, err error) {
	if errors.Is(err, api.AuthError) {
		l.Error().Msg("Failed attestation with an authentication error. Please enroll again.")
	} else if errors.Is(err, api.FormatError) {
		l.Error().Msg("Attestation failed. The server rejected our request. Make sure the agent is up to date.")
	} else if errors.Is(err, api.NetworkError) {
		l.Error().Msg("Attestation failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
	} else if errors.Is(err, api.ServerError) {
		l.Error().Msg("Attestation failed. The immune Guard server failed to process the request. Please try again later.")
	} else if errors.Is(err, api.PaymentError) {
		l.Error().Msg("Attestation failed. A payment is required to use the attestation service.")
	} else if errors.Is(err, ErrEncodeJson) {
		l.Error().Msg("Internal error while encoding firmware state.")
	} else if errors.Is(err, ErrReadPcr) {
		l.Error().Msg("Failed to read all PCR values.")
	} else if errors.Is(err, ErrRootKey) {
		l.Error().Msg("Failed to create or load root key.")
	} else if errors.Is(err, ErrAik) {
		l.Error().Msg("No key suitable for attestation found, please enroll first.")
	} else if errors.Is(err, ErrQuote) {
		l.Error().Msg("TPM 2.0 attestation failed.")
	} else if errors.Is(err, ErrOpenTrustAnchor) {
		l.Error().Msg("Cannot open TPM")
	} else if err != nil {
		l.Error().Msg("Attestation failed. An unknown error occured. Please try again later.")
	}
}

// LogInitErrors is a helper function to translate errors to text and log them directly
func LogInitErrors(l *zerolog.Logger, err error) {
	if errors.Is(err, ErrApiUrl) {
		l.Error().Msg("Invalid server URL.")
	} else if errors.Is(err, ErrStateDir) {
		l.Error().Msg("Can't create or write state directory, check permissions")
	} else if errors.Is(err, state.ErrNoPerm) {
		l.Error().Msg("Cannot read state, no permissions.")
	} else if errors.Is(err, ErrStateLoad) {
		l.Error().Msg("Failed to load state.")
	} else if errors.Is(err, ErrStateStore) {
		l.Error().Msg("Failed to store state.")
	} else {
		l.Error().Msg("Unknown error occured during initialization.")
	}
}

// LogUpdateConfigErrors is a helper function to translate errors to text and log them directly
func LogUpdateConfigErrors(l *zerolog.Logger, err error) {
	if errors.Is(err, ErrUpdateConfig) {
		l.Error().Msg("Failed to load configuration from server")
	} else if errors.Is(err, ErrStateStore) {
		l.Error().Msg("Failed to store state.")
	} else {
		l.Error().Msg("Unknown error occured during config update")
	}
}
