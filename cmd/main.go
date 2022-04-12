package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/alecthomas/kong"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"

	"github.com/google/go-tpm/tpm2"
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/attestation"
	"github.com/immune-gmbh/agent/v3/pkg/firmware"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tcg"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/immune-gmbh/agent/v3/pkg/util"
)

const (
	programName = "guard"
	programDesc = "immune Guard command-line utility"
)

var (
	releaseId              string = "unknown"
	defaultEndorsementAuth string = ""
	defaultNameHint        string = "Server"
	cli                    rootCmd
)

type globalOptions struct {
	// on-disk state
	State *state.State

	// derived from cli opts
	Client          api.Client
	Anchor          tcg.TrustAnchor
	EndorsementAuth string
}

type verboseFlag bool

func (v verboseFlag) BeforeApply() error {
	logrus.SetLevel(logrus.DebugLevel)
	return nil
}

type traceFlag bool

func (v traceFlag) BeforeApply() error {
	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetReportCaller(true)
	return nil
}

type rootCmd struct {
	// Global options
	Server   *url.URL    `name:"server" help:"immune SaaS API URL" default:"${server_default_url}" type:"*url.URL"`
	CA       string      `name:"server-ca" help:"immune SaaS API CA (PEM encoded)" optional type:"path"`
	StateDir string      `name:"state-dir" default:"${state_default_dir}" help:"Directory holding the cli state" type:"path"`
	LogFlag  bool        `name:"log" help:"Force log output on and text UI off"`
	Verbose  verboseFlag `help:"Enable verbose mode. Implies --log"`
	Trace    traceFlag   `hidden`
	Colors   bool        `help:"Force colors on for all console outputs (default: autodetect)"`

	// Subcommands
	Report reportCmd `cmd:"" help:"Generates a platform report"`
	Attest attestCmd `cmd:"" help:"Attests platform integrity of device"`
	Enroll enrollCmd `cmd:"" help:"Enrolls device at the immune SaaS backend"`
}

type enrollCmd struct {
	NoAttest bool   `help:"Don't attest after successful enrollment" default:"false"`
	Token    string `arg:"" required:"" name:"token" help:"Enrollment authentication token"`
	Name     string `arg:"" optional:"" name:"name hint" help:"Name to assign to the device. May get suffixed by a counter if already taken. Defaults to the hostname."`
	TPM      string `name:"tpm" default:"${tpm_default_path}" help:"TPM device: device path (${tpm_default_path}) or mssim, sgx, swtpm/net url (mssim://localhost, sgx://localhost, net://localhost:1234) or 'dummy' for dummy TPM"`
	DummyTPM bool   `name:notpm help:"Force using insecure dummy TPM if this device has no real TPM"`
}

type attestCmd struct {
}

type reportCmd struct {
	Show bool   `help:"Show output instead of writing it to file" default:"false"`
	Out  string `arg:"" optional:"" name:"out" default:"." help:"Absolute directory path to newly generated report" type:"path"`
}

func (enroll *enrollCmd) Run(glob *globalOptions) error {
	ctx := context.Background()
	if enroll.DummyTPM {
		glob.State.TPM = state.DummyTPMIdentifier
	} else {
		glob.State.TPM = enroll.TPM
	}

	if err := openTPM(glob); err != nil {
		if glob.State.TPM != state.DummyTPMIdentifier {
			tui.SetUIState(tui.StSelectTAFailed)
		}
		return err
	}
	tui.SetUIState(tui.StSelectTASuccess)

	if err := attestation.Enroll(ctx, &glob.Client, enroll.Token, glob.EndorsementAuth, defaultNameHint, glob.Anchor, glob.State); err != nil {
		tui.SetUIState(tui.StEnrollFailed)
		return err
	}

	// incorporate dummy TPM state
	if stub, ok := glob.Anchor.(*tcg.SoftwareAnchor); ok {
		if st, err := stub.Store(); err != nil {
			logrus.Debugf("SoftwareAnchor.Store: %s", err)
			logrus.Errorf("Failed to save stub TPM state to disk")
		} else {
			glob.State.StubState = st
		}
	}

	// XXX don't join paths on every occasion, provide file name globally
	if err := glob.State.Store(path.Join(cli.StateDir, "keys")); err != nil {
		logrus.Debugf("Store(%s): %s", cli.StateDir, err)
		logrus.Errorf("Failed to save activated keys to disk")
		return err
	}

	tui.SetUIState(tui.StEnrollSuccess)
	logrus.Infof("Device enrolled")
	if enroll.NoAttest {
		logrus.Infof("You can now attest with \"%s attest\"", os.Args[0])
		return nil
	}

	return doAttest(glob, ctx)
}

func (attest *attestCmd) Run(glob *globalOptions) error {
	ctx := context.Background()

	if !glob.State.IsEnrolled() {
		logrus.Errorf("No previous state found, please enroll first.")
		return errors.New("no-state")
	}

	if err := openTPM(glob); err != nil {
		return err
	}

	return doAttest(glob, ctx)
}

func doAttest(glob *globalOptions, ctx context.Context) error {
	appraisal, webLink, err := attestation.Attest(ctx, &glob.Client, glob.EndorsementAuth, glob.Anchor, glob.State, false)
	if err != nil {
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}
	tui.SetUIState(tui.StAttestationSuccess)
	logrus.Infof("Attestation successful")

	if appraisal.Verdict.Result {
		tui.SetUIState(tui.StDeviceTrusted)
		tui.SetUIState(tui.StChainAllGood)
	} else {
		tui.SetUIState(tui.StDeviceVulnerable)
		if !appraisal.Verdict.SupplyChain {
			tui.SetUIState(tui.StChainFailSupplyChain)
		} else if !appraisal.Verdict.Configuration {
			tui.SetUIState(tui.StChainFailConfiguration)
		} else if !appraisal.Verdict.Firmware {
			tui.SetUIState(tui.StChainFailFirmware)
		} else if !appraisal.Verdict.Bootloader {
			tui.SetUIState(tui.StChainFailBootloader)
		} else if !appraisal.Verdict.OperatingSystem {
			tui.SetUIState(tui.StChainFailOperatingSystem)
		} else if !appraisal.Verdict.EndpointProtection {
			tui.SetUIState(tui.StChainFailEndpointProtection)
		}
	}

	tui.ShowAppraisalLink(webLink)
	if webLink != "" {
		logrus.Infof("See detailed results here: %s", webLink)
	}

	if appraisal, err := json.MarshalIndent(*appraisal, "", "  "); err == nil {
		logrus.Debugln(string(appraisal))
	}

	return nil
}

func (report *reportCmd) Run(glob *globalOptions) error {
	if glob.State == nil {
		logrus.Errorf("No previous state found, please enroll first.")
		return errors.New("no-state")
	}

	// collect firmware info
	a, err := tcg.OpenTPM(glob.State.TPM, glob.State.StubState)
	if err != nil {
		logrus.Debugf("openAndClearTPM(cli.TPM, glob): %s", err.Error())
		logrus.Warnf("Cannot open TPM: %s", glob.State.TPM)
	}
	glob.Anchor = a
	var conn io.ReadWriteCloser
	if anch, ok := glob.Anchor.(*tcg.TCGAnchor); ok {
		conn = anch.Conn
	}
	fwProps, err := firmware.GatherFirmwareData(conn, &glob.State.Config)
	if err != nil {
		logrus.Warnf("Failed to gather firmware state")
		fwProps = api.FirmwareProperties{}
	}
	fwProps.Agent.Release = releaseId

	// read PCRs
	pcrValues, err := glob.Anchor.PCRValues(tpm2.Algorithm(glob.State.Config.PCRBank), glob.State.Config.PCRs)
	if err != nil {
		logrus.Debugf("tcg.PCRValues(glob.TpmConn, pcrSel): %s", err.Error())
		logrus.Error("Failed read all PCR values")
		return err
	}

	// serialize
	evidence := api.Evidence{
		Type:     api.EvidenceType,
		PCRs:     pcrValues,
		Firmware: fwProps,
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		logrus.Debugf("json.Marshal(Evidence): %s", err.Error())
		logrus.Fatalf("Internal error while encoding firmware state. This is a bug, please report it to bugs@immu.ne.")
	}

	if !report.Show {
		abs, err := filepath.Abs(report.Out)
		if err != nil {
			return err
		}
		host, err := os.Hostname()
		if err != nil {
			return err
		}
		path := abs + "/" + host + ".json"
		if err := ioutil.WriteFile(path, evidenceJSON, 0644); err != nil {
			return err
		}
		logrus.Infof("Report created: %s", path)
	} else {
		fmt.Println(string(evidenceJSON))
	}

	return nil
}

func openTPM(glob *globalOptions) error {
	a, err := tcg.OpenTPM(glob.State.TPM, glob.State.StubState)
	if err != nil {
		logrus.Debugf("tcg.OpenTPM(glob.State.TPM, glob.State.StubState): %s", err.Error())
		logrus.Errorf("Cannot open TPM: %s", glob.State.TPM)
		return err
	}

	glob.Anchor = a
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	glob := globalOptions{
		EndorsementAuth: defaultEndorsementAuth,
	}

	// add info about build to description
	desc := programDesc + " " + releaseId + " (" + runtime.GOARCH + ")"

	// find a state dir we can access
	var stateDir string
	for _, s := range state.DefaultStateDirs() {
		err := os.MkdirAll(s, os.ModeDir|0750)
		if err != nil {
			continue
		}
		path := filepath.Join(s, "testfile")
		fd, err := os.Create(path)
		if err != nil {
			continue
		}

		fd.Close()
		os.Remove(path)
		stateDir = s
		break
	}

	// Parse common cli options
	ctx := kong.Parse(&cli,
		kong.Name(programName),
		kong.Description(desc),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}),
		kong.Vars{
			"tpm_default_path":   state.DefaultTPMDevice(),
			"state_default_dir":  stateDir,
			"server_default_url": "https://api.immu.ne/v2",
		},
		kong.Bind(&glob))

	initUI(cli.Colors, cli.LogFlag || bool(cli.Verbose) || bool(cli.Trace))

	// tell who we are
	logrus.Debug(desc)

	// bail out if not root
	root, err := util.IsRoot()
	if err != nil {
		logrus.Warn("Can't check user. It is recommended to run as administrator or root user")
		logrus.Debugf("util.IsRoot(): %s", err.Error())
	} else if !root {
		tui.SetUIState(tui.StNoRoot)
		logrus.Error("This program must be run with elevated privileges")
		return 1
	}

	// check for statedir after parsing opts, b/c opts can change it
	if stateDir == "" {
		logrus.Warnf("Cannot write to state directories %#v", state.DefaultStateDirs())
		stateDir = os.TempDir() // XXX
	}

	if err := initClient(&glob); err != nil {
		tui.DumpErr()
		return 1
	}

	// fetch/refresh configuration
	if err := initState(stateDir, &glob); err != nil {
		logrus.Error("Cannot restore state")
		tui.DumpErr()
		return 1
	}

	// Run the selected subcommand
	if err := ctx.Run(&glob); err != nil {
		tui.DumpErr()
		return 1
	} else {
		return 0
	}
}

func initUI(forceColors bool, forceLog bool) {
	notty := os.Getenv("TERM") == "dumb" || (!isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsCygwinTerminal(os.Stdout.Fd()))

	// honor NO_COLOR env var as per https://no-color.org/ like the colors library we use does, too
	_, noColors := os.LookupEnv("NO_COLOR")

	if forceColors || (!notty && !noColors) {
		logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
		logrus.SetOutput(colorable.NewColorableStdout())
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{DisableColors: noColors && !forceColors})
		logrus.SetOutput(os.Stdout)
	}

	if !forceLog && !notty {
		tui.Init()
		logrus.SetLevel(logrus.ErrorLevel)
		logrus.SetOutput(tui.Err)
	}
}

// load and migrate on-disk state
func initState(stateDir string, glob *globalOptions) error {
	// XXX fix this directory confusion once and for all; also see cli.StateDir...
	statePath := path.Join(stateDir, "keys")

	// load and migrate state
	st, update, err := state.LoadState(stateDir)
	if errors.Is(err, state.ErrNotExist) {
		logrus.Info("No previous state found")
		glob.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		logrus.Error("Cannot read state, no permissions")
		return err
	} else if err != nil {
		return err
	} else {
		glob.State = st
	}
	if update {
		logrus.Debugf("Migrating state file to newest version")
		if err := glob.State.Store(statePath); err != nil {
			logrus.Debugf("Store(%s): %s", cli.StateDir, err)
			return err
		}
	}

	// see if the server has a new config for us
	update, err = glob.State.EnsureFresh(&glob.Client)
	if err != nil {
		logrus.Debugf("Fetching fresh config: %s", err)
		return err
	}
	if update {
		logrus.Debugf("Storing new config from server")
		if err := glob.State.Store(statePath); err != nil {
			logrus.Debugf("Store(%s): %s", cli.StateDir, err)
			return err
		}
	}

	return nil
}

func initClient(glob *globalOptions) error {
	var caCert *x509.Certificate
	if cli.CA != "" {
		buf, err := ioutil.ReadFile(cli.CA)
		if err != nil {
			logrus.Errorf("Cannot read '%s': %s", cli.CA, err.Error())
			return err
		}

		if pem, _ := pem.Decode(buf); pem != nil {
			buf = pem.Bytes
		}

		caCert, err = x509.ParseCertificate(buf)
		if err != nil {
			logrus.Errorf("CA certificate ill-formed: %s", err.Error())
			return err
		}
	}

	glob.Client = api.NewClient(cli.Server, caCert, releaseId)
	return nil
}
