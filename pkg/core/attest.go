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
	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/ima"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func readAllPCRBanks(ctx context.Context, anchor tcg.TrustAnchor) ([]int, map[string]map[string]api.Buffer, error) {
	// read all PCRs
	allPCRs, err := anchor.AllPCRValues()
	if err != nil {
		logrus.Debugf("tcg.AllPCRValues(): %s", err.Error())
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
				logrus.Debugf("strconv.Atoi(): %s", err.Error())
				logrus.Error("Failed to parse PCR index")
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

func (core *Core) Attest(ctx context.Context, dumpEvidenceTo string, dryRun bool) (*api.Appraisal, string, error) {
	var conn io.ReadWriteCloser
	if anch, ok := core.Anchor.(*tcg.TCGAnchor); ok {
		conn = anch.Conn
	}

	// collect firmware info
	tui.SetUIState(tui.StCollectFirmwareInfo)
	logrus.Info("Collecting firmware info")
	fwProps, err := firmware.GatherFirmwareData(conn, &core.State.Config)
	if err != nil {
		logrus.Warnf("Failed to gather firmware state")
		fwProps = api.FirmwareProperties{}
	}
	fwProps.Agent.Release = *core.ReleaseId

	// transform firmware info into json and crypto-safe canonical json representations
	fwPropsJSON, err := json.Marshal(fwProps)
	if err != nil {
		logrus.Debugf("json.Marshal(FirmwareProperties): %s", err.Error())
		logrus.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}
	fwPropsJCS, err := jcs.Transform(fwPropsJSON)
	if err != nil {
		logrus.Debugf("jcs.Transform(FirmwareProperties): %s", err.Error())
		logrus.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}
	fwPropsHash := sha256.Sum256(fwPropsJCS)

	toQuote, allPCRs, err := readAllPCRBanks(ctx, core.Anchor)
	if err != nil {
		logrus.Debugf("readAllPCRBanks(): %s", err.Error())
		logrus.Error("Failed to read all PCR values")
		return nil, "", err
	}

	// load Root key
	tui.SetUIState(tui.StQuotePCR)
	logrus.Info("Signing attestation data")
	rootHandle, rootPub, err := core.Anchor.CreateAndLoadRoot(core.EndorsementAuth, core.State.Root.Auth, &core.State.Config.Root.Public)
	if err != nil {
		logrus.Debugf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		logrus.Error("Failed to create root key")
		return nil, "", err
	}
	defer rootHandle.Flush(core.Anchor)

	// make sure we're on the right TPM
	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		logrus.Debugf("Name(rootPub): %s", err)
		logrus.Error("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return nil, "", err
	}

	// check the root name. this will change if the endorsement proof value is changed
	if !api.EqualNames(&rootName, &core.State.Root.Name) {
		logrus.Error("Failed to recreate enrolled root key. Your TPM was reset, please enroll again.")
		return nil, "", errors.New("root name changed")
	}

	// load AIK
	aik, ok := core.State.Keys["aik"]
	if !ok {
		logrus.Errorf("No key suitable for attestation found, please enroll first.")
		return nil, "", errors.New("no-aik")
	}
	aikHandle, err := core.Anchor.LoadDeviceKey(rootHandle, core.State.Root.Auth, aik.Public, aik.Private)
	if err != nil {
		logrus.Debugf("LoadDeviceKey(..): %s", err)
		logrus.Error("Failed to load AIK")
		return nil, "", err
	}
	defer aikHandle.Flush(core.Anchor)
	rootHandle.Flush(core.Anchor)

	// convert used PCR banks to tpm2.Algorithm selection for quote
	var algs []tpm2.Algorithm
	for k := range allPCRs {
		alg, err := strconv.ParseInt(k, 10, 16)
		if err != nil {
			logrus.Debugf("ParseInt failed: %s", err)
			logrus.Error("Invalid PCR bank selector")
			return nil, "", err
		}
		algs = append(algs, tpm2.Algorithm(alg))
	}

	// generate quote
	logrus.Traceln("generate quote")
	quote, sig, err := core.Anchor.Quote(aikHandle, aik.Auth, fwPropsHash[:], algs, toQuote)
	if err != nil || (sig.ECC == nil && sig.RSA == nil) {
		logrus.Debugf("TPM2_Quote failed: %s", err)
		logrus.Error("TPM 2.0 attestation failed")
		return nil, "", err
	}
	aikHandle.Flush(core.Anchor)

	// fetch the runtime measurment log
	fwProps.IMALog = new(api.ErrorBuffer)
	ima.ReportIMALog(fwProps.IMALog)

	cookie, _ := api.Cookie(rand.Reader)
	evidence := api.Evidence{
		Type:      api.EvidenceType,
		Quote:     &quote,
		Signature: &sig,
		Algorithm: strconv.Itoa(int(core.State.Config.PCRBank)),
		PCRs:      allPCRs[strconv.Itoa(int(core.State.Config.PCRBank))],
		AllPCRs:   allPCRs,
		Firmware:  fwProps,
		Cookie:    cookie,
	}

	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		logrus.Debugf("json.Marshal(Evidence): %s", err.Error())
		logrus.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}

	if dumpEvidenceTo == "-" {
		fmt.Println(string(evidenceJSON))
	} else if dumpEvidenceTo != "" {
		path := dumpEvidenceTo + ".evidence.json"
		if err := os.WriteFile(path, evidenceJSON, 0644); err != nil {
			return nil, "", err
		}
		logrus.Infof("Dumped evidence json: %s", path)
	}

	if dryRun {
		return nil, "", nil
	}

	// API call
	tui.SetUIState(tui.StSendEvidence)
	logrus.Info("Sending report to immune Guard cloud")
	attestResp, webLink, err := core.Client.Attest(ctx, aik.Credential, evidence)
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		logrus.Error("Failed attestation with an authentication error. Please enroll again.")
		return nil, "", err
	} else if errors.Is(err, api.FormatError) {
		logrus.Error("Attestation failed. The server rejected our request. Make sure the agent is up to date.")
		return nil, "", err
	} else if errors.Is(err, api.NetworkError) {
		logrus.Error("Attestation failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return nil, "", err
	} else if errors.Is(err, api.ServerError) {
		logrus.Error("Attestation failed. The immune Guard server failed to process the request. Please try again later.")
		return nil, "", err
	} else if errors.Is(err, api.PaymentError) {
		logrus.Error("Attestation failed. A payment is required to use the attestation service.")
		return nil, "", err
	} else if err != nil {
		logrus.Error("Attestation failed. An unknown error occured. Please try again later.")
		logrus.Debugf("client.Attest(..): %s", err.Error())
		return nil, "", err
	}
	return attestResp, webLink, nil
}
