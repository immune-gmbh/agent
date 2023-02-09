package cli

import (
	"io"
	"os"
	"runtime"

	"github.com/alecthomas/kong"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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
	log.Logger = log.Level(zerolog.DebugLevel)
	return nil
}

type traceFlag bool

func (v traceFlag) BeforeApply() error {
	log.Logger = log.Logger.With().Caller().Logger().Level(zerolog.TraceLevel)
	return nil
}

type rootCmd struct {
	// Global options
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

func initUI(forceColors bool, forceLog bool) io.Writer {
	notty := os.Getenv("TERM") == "dumb" || (!isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsCygwinTerminal(os.Stdout.Fd()))

	// honor NO_COLOR env var as per https://no-color.org/ like the colors library we use does, too
	_, noColors := os.LookupEnv("NO_COLOR")

	cw := zerolog.ConsoleWriter{
		Out:        nil,
		NoColor:    false,
		TimeFormat: "15:04:05"}

	// handle different console environments
	// if tui is disabled, then the log is our ui; so we use stdout
	cw.NoColor = (noColors || notty) && !forceColors
	if cw.NoColor {
		cw.Out = os.Stdout
	} else {
		cw.Out = colorable.NewColorableStdout()
	}

	// use tui instead of log as ui
	if !forceLog && !notty {
		tui.Init(cw.NoColor)
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		cw.Out = tui.Err
	}

	// apply settings to global default logger
	log.Logger = log.Output(cw)
	return cw
}

func RunCommandLineTool() int {
	agentCore := core.NewCore()

	// add info about build to description
	desc := programDesc + " " + *agentCore.ReleaseId + " (" + runtime.GOARCH + ")"

	// set global log level to trace so individual loggers can be set to all levels
	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	// set default global logger log level before kong possibly overrides it
	log.Logger = log.Level(zerolog.InfoLevel)

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
			// setting the TPM default path here is incompatible with future cross-platform client/server agent connections
			"tpm_default_path":  state.DefaultTPMDevice(),
			"state_default_dir": state.DefaultStateDir(),
		},
	}
	options = append(options, osSpecificCommands()...)

	// hide --standalone when not on windows; only windows supports connecting to agent service
	if runtime.GOOS != "windows" {
		options = append(options, kong.IgnoreFields("Standalone"))
	}

	// Parse common cli options
	var cli rootCmd
	ctx := kong.Parse(&cli, options...)

	// init UI and determine a std log output for logging from remote agents
	// when running as svc client we don't want tui b/c the tui states are not transmitted
	runSvcClient := runtime.GOOS == "windows" && !cli.Attest.Standalone && !cli.Enroll.Standalone
	stdLogOut := initUI(cli.Colors, cli.LogFlag || bool(cli.Verbose) || bool(cli.Trace) || runSvcClient)

	// tell who we are
	log.Debug().Msg(desc)

	// bail out if not root
	root, err := util.IsRoot()
	if err != nil {
		log.Warn().Msg("Can't check user. It is recommended to run as administrator or root user")
		log.Debug().Err(err).Msg("util.IsRoot()")
	} else if !root {
		tui.SetUIState(tui.StNoRoot)
		log.Error().Msg("This program must be run with elevated privileges")
		return 1
	}

	// init agent core
	if err := agentCore.Init(cli.StateDir, &log.Logger); err != nil {
		core.LogInitErrors(&log.Logger, err)
		tui.DumpErr()
		return 1
	}

	// Run the selected subcommand
	if err := ctx.Run(agentCore, &stdLogOut); err != nil {
		tui.DumpErr()
		return 1
	} else {
		return 0
	}
}
