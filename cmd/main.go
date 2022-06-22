package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/attestation"
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
	defaultServerURL       string = "https://api.immu.ne/v2"
	cli                    rootCmd
)

type globalOptions struct {
	// on-disk state
	State     *state.State
	StatePath string

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
	Server   *url.URL    `name:"server" help:"immune SaaS API URL" type:"*url.URL"`
	CA       string      `name:"server-ca" help:"immune SaaS API CA (PEM encoded)" optional type:"path"`
	StateDir string      `name:"state-dir" default:"${state_default_dir}" help:"Directory holding the cli state" type:"path"`
	LogFlag  bool        `name:"log" help:"Force log output on and text UI off"`
	Verbose  verboseFlag `help:"Enable verbose mode, implies --log"`
	Trace    traceFlag   `hidden`
	Colors   bool        `help:"Force colors on for all console outputs (default: autodetect)"`

	// Subcommands
	Attest attestCmd `cmd:"" help:"Attests platform integrity of device"`
	Enroll enrollCmd `cmd:"" help:"Enrolls device at the immune SaaS backend"`
}

type enrollCmd struct {
	NoAttest bool   `help:"Don't attest after successful enrollment" default:"false"`
	Token    string `arg:"" required:"" name:"token" help:"Enrollment authentication token"`
	Name     string `arg:"" optional:"" name:"name hint" help:"Name to assign to the device. May get suffixed by a counter if already taken. Defaults to the hostname."`
	TPM      string `name:"tpm" default:"${tpm_default_path}" help:"TPM device: device path (${tpm_default_path}) or mssim, sgx, swtpm/net url (mssim://localhost, sgx://localhost, net://localhost:1234) or 'dummy' for dummy TPM"`
	DummyTPM bool   `name:"notpm" help:"Force using insecure dummy TPM if this device has no real TPM" default:"false"`
}

type attestCmd struct {
	DryRun bool   `name:"dry-run" help:"Do full attest but don't contact the immune servers" default:"false"`
	Dump   string `optional:"" name:"dump-report" help:"Specify a file to dump the security report to" type:"path"`
}

func (enroll *enrollCmd) Run(glob *globalOptions) error {
	ctx := context.Background()

	// store used TPM in state, use dummy TPM only if forced
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

	// when server is set on cmdline during enroll store it in state
	// so OS startup scripts can attest without needing to know the server URL
	if cli.Server != nil {
		glob.State.ServerURL = cli.Server
	}

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

	// save the new state to disk
	if err := glob.State.Store(glob.StatePath); err != nil {
		logrus.Debugf("Store(%s): %s", glob.StatePath, err)
		logrus.Errorf("Failed to save activated keys to disk")
		return err
	}

	tui.SetUIState(tui.StEnrollSuccess)
	logrus.Infof("Device enrolled")
	if enroll.NoAttest {
		logrus.Infof("You can now attest with \"%s attest\"", os.Args[0])
		return nil
	}

	return doAttest(glob, ctx, "", false)
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

	return doAttest(glob, ctx, attest.Dump, attest.DryRun)
}

func doAttest(glob *globalOptions, ctx context.Context, dumpReportTo string, dryRun bool) error {
	appraisal, webLink, err := attestation.Attest(ctx, &glob.Client, glob.EndorsementAuth, glob.Anchor, glob.State, releaseId, dumpReportTo, dryRun)
	if err != nil {
		tui.SetUIState(tui.StAttestationFailed)
		return err
	}

	inProgress := appraisal == nil

	if inProgress {
		tui.SetUIState(tui.StAttestationRunning)
		logrus.Infof("Attestation in progress, results become available later")
		tui.ShowAppraisalLink(webLink)
		if webLink != "" {
			logrus.Infof("See detailed results here: %s", webLink)
		}
		return nil
	} else {
		tui.SetUIState(tui.StAttestationSuccess)
		logrus.Infof("Attestation successful")
	}

	if dryRun {
		return nil
	}

	if appraisal.Verdict.Result == api.Trusted {
		tui.SetUIState(tui.StDeviceTrusted)
		tui.SetUIState(tui.StChainAllGood)
	} else {
		tui.SetUIState(tui.StDeviceVulnerable)
		if appraisal.Verdict.SupplyChain == api.Vulnerable {
			tui.SetUIState(tui.StChainFailSupplyChain)
		} else if appraisal.Verdict.Configuration == api.Vulnerable {
			tui.SetUIState(tui.StChainFailConfiguration)
		} else if appraisal.Verdict.Firmware == api.Vulnerable {
			tui.SetUIState(tui.StChainFailFirmware)
		} else if appraisal.Verdict.Bootloader == api.Vulnerable {
			tui.SetUIState(tui.StChainFailBootloader)
		} else if appraisal.Verdict.OperatingSystem == api.Vulnerable {
			tui.SetUIState(tui.StChainFailOperatingSystem)
		} else if appraisal.Verdict.EndpointProtection == api.Vulnerable {
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
			"tpm_default_path":  state.DefaultTPMDevice(),
			"state_default_dir": state.DefaultStateDir(),
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

	if err := initClient(&glob); err != nil {
		tui.DumpErr()
		return 1
	}

	// fetch/refresh configuration
	if err := initState(cli.StateDir, &glob); err != nil {
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
	// stateDir is either the OS-specific default or what we get from the CLI
	if stateDir == "" {
		logrus.Error("No state directory specified")
		return errors.New("state parameter empty")
	}

	// test if the state directory is writable
	{
		err := os.MkdirAll(stateDir, os.ModeDir|0750)
		if err != nil {
			logrus.Errorf("Can't create state directory, check permissions: %s", stateDir)
			return err
		}
		tmp := filepath.Join(stateDir, "testfile")
		fd, err := os.Create(tmp)
		if err != nil {
			logrus.Errorf("Can't write in state directory, check permissions: %s", stateDir)
			return err
		}
		fd.Close()
		os.Remove(tmp)
	}

	glob.StatePath = path.Join(stateDir, "keys")

	// load and migrate state
	st, update, err := state.LoadState(glob.StatePath)
	if errors.Is(err, state.ErrNotExist) {
		logrus.Info("No previous state found")
		glob.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		logrus.Error("Cannot read state, no permissions")
		return err
	} else if err != nil {
		logrus.Debugf("state.LoadState(%s): %s", glob.StatePath, err)
		return err
	} else {
		glob.State = st
	}
	if update {
		logrus.Debugf("Migrating state file to newest version")
		if err := glob.State.Store(glob.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", glob.StatePath, err)
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
		if err := glob.State.Store(glob.StatePath); err != nil {
			logrus.Debugf("Store(%s): %s", glob.StatePath, err)
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

	// use server URL in state, if any, with cmdline setting taking precedence
	var server *url.URL
	if cli.Server != nil {
		server = cli.Server
	} else if glob.State.ServerURL != nil {
		server = glob.State.ServerURL
	} else {
		var err error
		server, err = url.Parse(defaultServerURL)
		if err != nil {
			logrus.Fatal("default server URL is invalid")
		}
	}

	glob.Client = api.NewClient(server, caCert, releaseId)
	return nil
}
