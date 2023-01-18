package cli

import (
	"errors"
	"net/url"
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
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	return nil
}

type traceFlag bool

func (v traceFlag) BeforeApply() error {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Logger.With().Caller().Logger()
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

	cw := zerolog.ConsoleWriter{
		Out:        colorable.NewColorableStdout(),
		NoColor:    false,
		TimeFormat: "15:04:05"}

	// handle different console environments
	// if tui is disabled, then the log is our ui; so we use stdout
	if forceColors || (!notty && !noColors) {
		cw.NoColor = false
		cw.Out = colorable.NewColorableStdout()
	} else {
		cw.NoColor = noColors && !forceColors
		cw.Out = os.Stdout
	}

	// use tui instead of log as ui
	if !forceLog && !notty {
		tui.Init()
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		cw.Out = tui.Err
	}

	// apply settings to global default logger
	log.Logger = log.Output(cw)
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
	if err := agentCore.Init(cli.StateDir, cli.CA, cli.Server, &log.Logger); err != nil {
		if errors.Is(err, core.ErrApiUrl) {
			log.Error().Msg("Invalid server URL.")
		} else if errors.Is(err, core.ErrStateDir) {
			log.Error().Msgf("Can't create or write state directory, check permissions: %s", cli.StateDir)
		} else if errors.Is(err, state.ErrNoPerm) {
			log.Error().Msg("Cannot read state, no permissions.")
		} else if errors.Is(err, core.ErrStateLoad) {
			log.Error().Msg("Failed to load state.")
		} else if errors.Is(err, core.ErrStateStore) {
			log.Error().Msg("Failed to store state.")
		} else {
			log.Error().Msg("Unknown error occured during initialization.")
		}

		tui.DumpErr()
		return 1
	}

	// be sure to run this after we have a client
	if err := agentCore.UpdateConfig(); err != nil {
		if errors.Is(err, core.ErrUpdateConfig) {
			log.Error().Msg("Failed to load configuration from server")
		} else {
			log.Error().Msg("Unknown error occured during config update")
		}
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
