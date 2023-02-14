package core

import (
	"errors"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/rs/zerolog"
)

type AttestationClientError string

func (e AttestationClientError) Error() string {
	return string(e)
}

func (e AttestationClientError) Is(target error) bool {
	// this is a bit hacky but will also work for api package errors f.e.
	return string(e) == target.Error()
}

var (
	ErrEncodeJson      = AttestationClientError("json encoding")
	ErrReadPcr         = AttestationClientError("read pcr")
	ErrRootKey         = AttestationClientError("create or load root key")
	ErrAik             = AttestationClientError("create or load aik")
	ErrQuote           = AttestationClientError("tpm quote")
	ErrUnknown         = AttestationClientError("internal error")
	ErrEndorsementKey  = AttestationClientError("create or load EK")
	ErrEnroll          = AttestationClientError("internal enrollment error")
	ErrApiResponse     = AttestationClientError("unexpected api response")
	ErrOpenTrustAnchor = AttestationClientError("open trust anchor")
	ErrStateDir        = AttestationClientError("create or write state dir")
	ErrStateLoad       = AttestationClientError("other state load error")
	ErrStateStore      = AttestationClientError("other state store error")
	ErrUpdateConfig    = AttestationClientError("fetch config from server")
)

// LogEnrollErrors is a helper function to translate errors to text and log them directly
func LogEnrollErrors(l *zerolog.Logger, err error) {
	if errors.Is(err, api.AuthError) {
		l.Error().Msg("Failed enrollment with an authentication error. Make sure the enrollment token is correct.")
	} else if errors.Is(err, api.FormatError) {
		l.Error().Msg("Enrollment failed. The server rejected our request. Make sure the agent is up to date.")
	} else if errors.Is(err, api.NetworkError) {
		l.Error().Msg("Enrollment failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
	} else if errors.Is(err, api.ServerError) {
		l.Error().Msg("Enrollment failed. The immune Guard server failed to process the request. Please try again later.")
	} else if errors.Is(err, api.PaymentError) {
		l.Error().Msg("Enrollment failed. A payment is required for further enrollments.")
	} else if errors.Is(err, ErrRootKey) {
		l.Error().Msg("Failed to create or load root key.")
	} else if errors.Is(err, ErrAik) {
		l.Error().Msg("Server refused to certify attestation key.")
	} else if errors.Is(err, ErrEndorsementKey) {
		l.Error().Msg("Cannot create Endorsement key.")
	} else if errors.Is(err, ErrEnroll) {
		l.Error().Msg("Internal error during enrollment.")
	} else if errors.Is(err, ErrApiResponse) {
		l.Error().Msg("Server resonse not understood. Is your agent up-to-date?")
	} else if errors.Is(err, ErrStateStore) {
		l.Error().Msg("Failed to store state.")
	} else if errors.Is(err, ErrOpenTrustAnchor) {
		l.Error().Msg("Cannot open TPM")
	} else if errors.Is(err, ErrUpdateConfig) {
		l.Error().Msg("Failed to load configuration from server")
	} else {
		l.Error().Msg("Enrollment failed. An unknown error occured. Please try again later.")
	}
}

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
	} else if errors.Is(err, ErrUpdateConfig) {
		l.Error().Msg("Failed to load configuration from server")
	} else if errors.Is(err, ErrStateStore) {
		l.Error().Msg("Failed to store state.")
	} else if err != nil {
		l.Error().Msg("Attestation failed. An unknown error occured. Please try again later.")
	}
}

// LogInitErrors is a helper function to translate errors to text and log them directly
func LogInitErrors(l *zerolog.Logger, err error) {
	if errors.Is(err, ErrStateDir) {
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
