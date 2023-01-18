package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/gowebpki/jcs"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/ima"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func (ac *AttestationClient) readAllPCRBanks(ctx context.Context) ([]int, map[string]map[string]api.Buffer, error) {
	// read all PCRs
	allPCRs, err := ac.Anchor.AllPCRValues()
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.AllPCRValues()")
		return nil, nil, err
	}

	// compute pcr set to quote
	availPCR := make(map[string]uint32)
	for algo, bank := range allPCRs {
		if len(bank) == 0 {
			continue
		}
		var bits uint32
		for strpcr := range bank {
			pcr, err := strconv.Atoi(strpcr)
			if err != nil {
				ac.Log.Debug().Err(err).Msg("strconv.Atoi()")
				return nil, nil, err
			}
			if pcr < 32 {
				bits = bits | (1 << pcr)
			}
		}
		availPCR[algo] = bits
	}
	var toQuoteBits uint32 = 0xffffffff
	for _, bits := range availPCR {
		toQuoteBits = toQuoteBits & bits
	}
	var toQuoteInts []int
	for i := 0; i < 32; i++ {
		if toQuoteBits&(1<<i) != 0 {
			toQuoteInts = append(toQuoteInts, int(i))
		}
	}

	return toQuoteInts, allPCRs, nil
}

func (ac *AttestationClient) Attest(ctx context.Context, dumpEvidenceTo string, dryRun bool) (*api.Appraisal, string, error) {
	var conn io.ReadWriteCloser
	if anch, ok := ac.Anchor.(*tcg.TCGAnchor); ok {
		conn = anch.Conn
	}

	// collect firmware info
	tui.SetUIState(tui.StCollectFirmwareInfo)
	ac.Log.Info().Msg("Collecting firmware info")
	fwProps := firmware.GatherFirmwareData(conn, &ac.State.Config)
	fwProps.Agent.Release = *ac.ReleaseId

	// transform firmware info into json and crypto-safe canonical json representations
	fwPropsJSON, err := json.Marshal(fwProps)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("json.Marshal(FirmwareProperties)")
		return nil, "", ErrEncodeJson
	}
	fwPropsJCS, err := jcs.Transform(fwPropsJSON)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("jcs.Transform(FirmwareProperties)")
		return nil, "", ErrEncodeJson
	}
	fwPropsHash := sha256.Sum256(fwPropsJCS)

	toQuote, allPCRs, err := ac.readAllPCRBanks(ctx)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("readAllPCRBanks()")
		return nil, "", ErrReadPcr
	}

	// load Root key
	tui.SetUIState(tui.StQuotePCR)
	ac.Log.Info().Msg("Signing attestation data")
	rootHandle, rootPub, err := ac.Anchor.CreateAndLoadRoot(ac.EndorsementAuth, ac.State.Root.Auth, &ac.State.Config.Root.Public)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("tcg.CreateAndLoadRoot(..)")
		return nil, "", ErrRootKey
	}
	defer rootHandle.Flush(ac.Anchor)

	// make sure we're on the right TPM
	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("Name(rootPub)")
		return nil, "", ErrRootKey
	}

	// check the root name. this will change if the endorsement proof value is changed
	if !api.EqualNames(&rootName, &ac.State.Root.Name) {
		return nil, "", ErrRootKey
	}

	// load AIK
	aik, ok := ac.State.Keys["aik"]
	if !ok {
		return nil, "", ErrAik
	}
	aikHandle, err := ac.Anchor.LoadDeviceKey(rootHandle, ac.State.Root.Auth, aik.Public, aik.Private)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("LoadDeviceKey(..)")
		return nil, "", ErrAik
	}
	defer aikHandle.Flush(ac.Anchor)
	rootHandle.Flush(ac.Anchor)

	// convert used PCR banks to tpm2.Algorithm selection for quote
	var algs []tpm2.Algorithm
	for k := range allPCRs {
		alg, err := strconv.ParseInt(k, 10, 16)
		if err != nil {
			ac.Log.Debug().Err(err).Msg("ParseInt failed")
			return nil, "", ErrQuote
		}
		algs = append(algs, tpm2.Algorithm(alg))
	}

	// generate quote
	ac.Log.Trace().Msg("generate quote")
	quote, sig, err := ac.Anchor.Quote(aikHandle, aik.Auth, fwPropsHash[:], algs, toQuote)
	if err != nil || (sig.ECC == nil && sig.RSA == nil) {
		ac.Log.Debug().Err(err).Msg("TPM2_Quote failed")
		return nil, "", ErrQuote
	}
	aikHandle.Flush(ac.Anchor)

	// fetch the runtime measurment log
	//XXX 1) should only run on linux 2) must check errors 3) is placed here because fw report can't report data that should be omitted from quote and b/c this data is part of PCRs anyway
	fwProps.IMALog = new(api.ErrorBuffer)
	ima.ReportIMALog(fwProps.IMALog)

	cookie, _ := api.Cookie(rand.Reader)
	evidence := api.Evidence{
		Type:      api.EvidenceType,
		Quote:     &quote,
		Signature: &sig,
		Algorithm: strconv.Itoa(int(ac.State.Config.PCRBank)),
		PCRs:      allPCRs[strconv.Itoa(int(ac.State.Config.PCRBank))],
		AllPCRs:   allPCRs,
		Firmware:  fwProps,
		Cookie:    cookie,
	}

	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("json.Marshal(Evidence)")
		return nil, "", ErrEncodeJson
	}

	// XXX this should be handled outside of attest
	if dumpEvidenceTo == "-" {
		fmt.Println(string(evidenceJSON))
	} else if dumpEvidenceTo != "" {
		path := dumpEvidenceTo + ".evidence.json"
		if err := os.WriteFile(path, evidenceJSON, 0644); err != nil {
			return nil, "", err
		}
		ac.Log.Info().Msgf("Dumped evidence json: %s", path)
	}

	if dryRun {
		return nil, "", nil
	}

	// API call
	tui.SetUIState(tui.StSendEvidence)
	ac.Log.Info().Msg("Sending report to immune Guard cloud")
	attestResp, webLink, err := ac.Client.Attest(ctx, aik.Credential, evidence)
	if err != nil {
		ac.Log.Debug().Err(err).Msg("client.Attest(..)")

		// pass-through API errors and replace all others with ErrUnknown
		if !(errors.Is(err, api.AuthError) ||
			errors.Is(err, api.FormatError) ||
			errors.Is(err, api.NetworkError) ||
			errors.Is(err, api.ServerError) ||
			errors.Is(err, api.PaymentError)) {
			err = ErrUnknown
		}

		return nil, "", err
	}

	return attestResp, webLink, nil
}
