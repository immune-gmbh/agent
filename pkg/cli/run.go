package cli

import (
	"net/url"
	"os"
	"runtime"

	"github.com/alecthomas/kong"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/tui"
	"github.com/immune-gmbh/agent/v3/pkg/util"
)

const (
	programName = "guard"
	programDesc = "immune Guard command-line utility"
)

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
	CA       string      `name:"server-ca" help:"immune SaaS API CA (PEM encoded)" type:"path"`
	StateDir string      `name:"state-dir" default:"${state_default_dir}" help:"Directory holding the cli state" type:"path"`
	LogFlag  bool        `name:"log" help:"Force log output on and text UI off"`
	Verbose  verboseFlag `help:"Enable verbose mode, implies log"`
	Trace    traceFlag   `hidden:""`
	Colors   bool        `help:"Force colors on for all console outputs (default: autodetect)"`

	// Subcommands
	Attest  attestCmd  `cmd:"" help:"Attests platform integrity of device"`
	Enroll  enrollCmd  `cmd:"" help:"Enrolls device at the immune SaaS backend"`
	Collect collectCmd `cmd:"" help:"Only collect firmware data"`
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

func RunCommandLineTool() int {
	agentCore := core.NewCore()

	// add info about build to description
	desc := programDesc + " " + *agentCore.ReleaseId + " (" + runtime.GOARCH + ")"

	// Dynamically build Kong options
	options := []kong.Option{
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
		kong.Bind(&agentCore),
	}
	options = append(options, osSpecificCommands()...)

	// Parse common cli options
	var cli rootCmd
	ctx := kong.Parse(&cli, options...)

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

	// init agent core
	if err := agentCore.Init(cli.StateDir, cli.CA, cli.Server); err != nil {
		tui.DumpErr()
		return 1
	}

	// be sure to run this after we have a client
	if err := agentCore.UpdateConfig(); err != nil {
		tui.DumpErr()
		return 1
	}

	// Run the selected subcommand
	if err := ctx.Run(agentCore); err != nil {
		tui.DumpErr()
		return 1
	} else {
		return 0
	}
}
