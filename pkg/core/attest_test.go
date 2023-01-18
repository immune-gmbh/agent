package core

import (
	"context"
	"crypto/x509"
	"strconv"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
)

type testAnchor struct {
	Banks map[string]map[string]api.Buffer
}

func (testAnchor) CreateAndLoadRoot(endorsementAuth string, rootAuth string, tmpl *api.PublicKey) (tcg.Handle, api.PublicKey, error) {
	panic("unimplemented")
}
func (testAnchor) CreateAndCertifyDeviceKey(rootHandle tcg.Handle, rootAuth string, template api.KeyTemplate, authValue string) (api.Key, api.Buffer, error) {
	panic("unimplemented")
}
func (testAnchor) LoadDeviceKey(rootHandle tcg.Handle, rootAuth string, public api.PublicKey, private api.Buffer) (tcg.Handle, error) {
	panic("unimplemented")
}
func (testAnchor) ActivateDeviceKey(cred api.EncryptedCredential, endorsementAuth string, auth string, keyHandle tcg.Handle, ekHandle tcg.Handle, state *state.State) (string, error) {
	panic("unimplemented")
}
func (testAnchor) ReadEKCertificate() (*x509.Certificate, error) {
	panic("unimplemented")
}
func (testAnchor) GetEndorsementKey() (tcg.Handle, tpm2.Public, error) {
	panic("unimplemented")
}
func (a testAnchor) PCRValues(algorithm tpm2.Algorithm, pcr []int) (map[string]api.Buffer, error) {
	if bank, ok := a.Banks[strconv.Itoa(int(algorithm))]; ok {
		return bank, nil
	} else {
		panic("unimplemented")
	}
}
func (a testAnchor) AllPCRValues() (map[string]map[string]api.Buffer, error) {
	return a.Banks, nil
}
func (testAnchor) Quote(aikHandle tcg.Handle, aikAuth string, additional api.Buffer, banks []tpm2.Algorithm, pcrs []int) (api.Attest, api.Signature, error) {
	panic("unimplemented")
}
func (testAnchor) FlushAllHandles() {
	panic("unimplemented")
}
func (testAnchor) Close() {
	panic("unimplemented")
}

func TestToQuoteList(t *testing.T) {
	ctx := context.Background()
	agentCore := NewCore()
	agentCore.Log = &log.Logger

	// sha1 only
	agentCore.Anchor = testAnchor{
		Banks: map[string]map[string]api.Buffer{
			"11": {},
			"4": {
				"0": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"4": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"5": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}
	toQuote, allPcr, err := agentCore.readAllPCRBanks(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, toQuote)
	assert.NotEmpty(t, allPcr)

	// sha256 only
	agentCore.Anchor = testAnchor{
		Banks: map[string]map[string]api.Buffer{
			"11": {
				"0": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"4": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"5": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			"4": {},
		},
	}
	toQuote, allPcr, err = agentCore.readAllPCRBanks(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, toQuote)
	assert.NotEmpty(t, allPcr)

	// sha1 & sha256
	agentCore.Anchor = testAnchor{
		Banks: map[string]map[string]api.Buffer{
			"11": {
				"0": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"4": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"5": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			"4": {
				"0": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"4": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"5": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}
	toQuote, allPcr, err = agentCore.readAllPCRBanks(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, toQuote)
	assert.NotEmpty(t, allPcr)

	// subset sha1 & sha256
	agentCore.Anchor = testAnchor{
		Banks: map[string]map[string]api.Buffer{
			"11": {
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"4": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"5": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			"4": {
				"0": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"2": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				"3": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}
	toQuote, allPcr, err = agentCore.readAllPCRBanks(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{2, 3}, toQuote)
	assert.NotEmpty(t, allPcr)
}
