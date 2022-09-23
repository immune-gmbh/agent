package attestation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"

	"github.com/google/go-tpm/tpm2"
	"github.com/gowebpki/jcs"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/ima"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
)

func Attest(ctx context.Context, client *api.Client, endorsementAuth string, anchor tcg.TrustAnchor, st *state.State, releaseId string, dumpEvidenceTo string, dryRun bool) (*api.Appraisal, string, error) {
	var conn io.ReadWriteCloser
	if anch, ok := anchor.(*tcg.TCGAnchor); ok {
		conn = anch.Conn
	}

	// collect firmware info
	tui.SetUIState(tui.StCollectFirmwareInfo)
	logrus.Info("Collecting firmware info")
	fwProps, err := firmware.GatherFirmwareData(conn, &st.Config)
	if err != nil {
		log.Warnf("Failed to gather firmware state")
		fwProps = api.FirmwareProperties{}
	}
	fwProps.Agent.Release = releaseId

	// transform firmware info into json and crypto-safe canonical json representations
	fwPropsJSON, err := json.Marshal(fwProps)
	if err != nil {
		log.Debugf("json.Marshal(FirmwareProperties): %s", err.Error())
		log.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}
	fwPropsJCS, err := jcs.Transform(fwPropsJSON)
	if err != nil {
		log.Debugf("jcs.Transform(FirmwareProperties): %s", err.Error())
		log.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}
	fwPropsHash := sha256.Sum256(fwPropsJCS)

	// read selected PCRs
	pcrValues, err := anchor.PCRValues(tpm2.Algorithm(st.Config.PCRBank), st.Config.PCRs)
	if err != nil {
		log.Debugf("tcg.PCRValues(glob.TpmConn, pcrSel): %s", err.Error())
		log.Error("Failed to read selected PCR values")
		return nil, "", err
	}
	quotedPCR := []int{}
	for k := range pcrValues {
		if i, err := strconv.ParseInt(k, 10, 32); err == nil {
			quotedPCR = append(quotedPCR, int(i))
		}
	}

	// read all PCRs
	allPCRs, err := anchor.AllPCRValues()
	if err != nil {
		log.Debugf("tcg.AllPCRValues(): %s", err.Error())
		log.Error("Failed to read all PCR values")
		return nil, "", err
	}

	// load Root key
	tui.SetUIState(tui.StQuotePCR)
	logrus.Info("Signing attestation data")
	rootHandle, rootPub, err := anchor.CreateAndLoadRoot(endorsementAuth, st.Root.Auth, &st.Config.Root.Public)
	if err != nil {
		log.Debugf("tcg.CreateAndLoadRoot(..): %s", err.Error())
		log.Error("Failed to create root key")
		return nil, "", err
	}
	defer rootHandle.Flush(anchor)

	// make sure we're on the right TPM
	rootName, err := api.ComputeName(rootPub)
	if err != nil {
		log.Debugf("Name(rootPub): %s", err)
		log.Error("Internal error while vetting root key. This is a bug, please report it to bugs@immu.ne.")
		return nil, "", err
	}

	// check the root name. this will change if the endorsement proof value is changed
	if !api.EqualNames(&rootName, &st.Root.Name) {
		log.Error("Failed to recreate enrolled root key. Your TPM was reset, please enroll again.")
		return nil, "", errors.New("root name changed")
	}

	// load AIK
	aik, ok := st.Keys["aik"]
	if !ok {
		log.Errorf("No key suitable for attestation found, please enroll first.")
		return nil, "", errors.New("no-aik")
	}
	aikHandle, err := anchor.LoadDeviceKey(rootHandle, st.Root.Auth, aik.Public, aik.Private)
	if err != nil {
		log.Debugf("LoadDeviceKey(..): %s", err)
		log.Error("Failed to load AIK")
		return nil, "", err
	}
	defer aikHandle.Flush(anchor)
	rootHandle.Flush(anchor)

	// convert used PCR banks to tpm2.Algorithm selection for quote
	var algs []tpm2.Algorithm
	for k, _ := range allPCRs {
		alg, err := strconv.ParseInt(k, 10, 16)
		if err != nil {
			log.Debugf("ParseInt failed: %s", err)
			log.Error("Invalid PCR bank selector")
			return nil, "", err
		}
		algs = append(algs, tpm2.Algorithm(alg))
	}

	// generate quote
	log.Traceln("generate quote")
	quote, sig, err := anchor.Quote(aikHandle, aik.Auth, fwPropsHash[:], algs, quotedPCR)
	if err != nil || (sig.ECC == nil && sig.RSA == nil) {
		log.Debugf("TPM2_Quote failed: %s", err)
		log.Error("TPM 2.0 attestation failed")
		return nil, "", err
	}
	aikHandle.Flush(anchor)

	// fetch the runtime measurment log
	fwProps.IMALog = new(api.ErrorBuffer)
	ima.ReportIMALog(fwProps.IMALog)

	cookie, _ := api.Cookie(rand.Reader)
	evidence := api.Evidence{
		Type:      api.EvidenceType,
		Quote:     &quote,
		Signature: &sig,
		Algorithm: strconv.Itoa(int(st.Config.PCRBank)),
		PCRs:      pcrValues,
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
		if err := ioutil.WriteFile(path, evidenceJSON, 0644); err != nil {
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
	attestResp, webLink, err := client.Attest(ctx, aik.Credential, evidence)
	// HTTP-level errors
	if errors.Is(err, api.AuthError) {
		log.Error("Failed attestation with an authentication error. Please enroll again.")
		return nil, "", err
	} else if errors.Is(err, api.FormatError) {
		log.Error("Attestation failed. The server rejected our request. Make sure the agent is up to date.")
		return nil, "", err
	} else if errors.Is(err, api.NetworkError) {
		log.Error("Attestation failed. Cannot contact the immune Guard server. Make sure you're connected to the internet.")
		return nil, "", err
	} else if errors.Is(err, api.ServerError) {
		log.Error("Attestation failed. The immune Guard server failed to process the request. Please try again later.")
		return nil, "", err
	} else if errors.Is(err, api.PaymentError) {
		log.Error("Attestation failed. A payment is required to use the attestation service.")
		return nil, "", err
	} else if err != nil {
		log.Error("Attestation failed. An unknown error occured. Please try again later.")
		logrus.Debugf("client.Attest(..): %s", err.Error())
		return nil, "", err
	}
	return attestResp, webLink, nil
}
