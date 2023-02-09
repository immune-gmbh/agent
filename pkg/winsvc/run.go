//go:build windows

package winsvc

import (
	"context"
	"runtime"
	"time"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/ipc"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	SVC_NAME              = "immuneGuard"
	SVC_DESC              = "immune Guard Agent Service"
	defaultAttestInterval = time.Hour
)

var defaultAttestArgs = ipc.CmdArgsAttest{DryRun: false}

type Exponential struct {
	Min        time.Duration
	Max        time.Duration
	ErrorCount int
}

func (e *Exponential) Reset() {
	e.ErrorCount = 0
}

func (e *Exponential) Increase() time.Duration {
	if e.ErrorCount > 30 {
		e.ErrorCount = 30
	} else {
		e.ErrorCount++
	}
	backoff := e.Min * (1 << e.ErrorCount)
	if backoff > e.Max {
		backoff = e.Max
	}

	return backoff
}

type agentService struct {
	backoff          *Exponential
	agent            *ipc.SharedAgentResource
	cancelPipeServer context.CancelFunc
	svcReleaseId     *string
}

func (m *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	scheduleInterval := time.Millisecond
	m.backoff = &Exponential{Min: time.Minute, Max: defaultAttestInterval}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Info().Msgf("immune Guard agent service %s (%s) started", *m.svcReleaseId, runtime.GOARCH)

	defer func() {
		if err := recover(); err != nil {
			log.Error().Msgf("exiting due to panic: %v", err)
		}
		changes <- svc.Status{State: svc.StopPending}
	}()

loop:
	for {
		select {
		case <-time.After(scheduleInterval):
			scheduleInterval = m.runAttest()
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Info().Msg("stopping")
				m.cancelPipeServer()
				break loop
			default:
				log.Error().Msgf("unexpected control request #%d", c)
			}
		}
	}
	return
}

// XXX consider running agent ops in a goroutine to not block the winsvc messaging thread
// -> test what happens if I query status or stop service when long attest is running
func (m *agentService) runAttest() time.Duration {
	status := m.agent.Status()
	if !status.Enrolled {
		return defaultAttestInterval
	}

	// if the last operation is recent then reschedule accordingly
	if status.LastRun != nil && status.LastOperation != "" {
		d := time.Since(*status.LastRun)
		if d < defaultAttestInterval {
			return defaultAttestInterval - d
		}
	}

	// run attest and retry with exponential backoff in case of error or non exclusive access
	if exclusive, err := m.agent.TryAttest(context.Background(), nil, &defaultAttestArgs); err != nil {
		core.LogAttestErrors(&log.Logger, err)
		return m.backoff.Increase()
	} else if !exclusive {
		return m.backoff.Increase()
	}
	m.backoff.Reset()

	return defaultAttestInterval
}

func RunService() int {
	// init logging
	elog, err := eventlog.Open(SVC_NAME)
	if err != nil {
		return 255
	}
	defer elog.Close()

	// configure logging and redirect global logger output to event log
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Level(zerolog.InfoLevel)
	ew := &eventLogWriter{
		elog: elog,
		cw: &zerolog.ConsoleWriter{
			NoColor: true, PartsExclude: []string{zerolog.LevelFieldName, zerolog.TimestampFieldName},
		},
	}
	sew := zerolog.SyncWriter(ew)
	log.Logger = log.Logger.Output(sew)

	// bail out if not root
	root, err := util.IsRoot()
	if err != nil {
		log.Warn().Msg("Can't check user. It is recommended to run as administrator or root user")
		log.Debug().Err(err).Msg("util.IsRoot()")
	} else if !root {
		log.Error().Msg("This program must be run with elevated privileges")
		return 1
	}

	// init agent core
	agent := core.NewCore()
	if err := agent.Init(state.DefaultStateDir(), &log.Logger); err != nil {
		core.LogInitErrors(&log.Logger, err)
		return 1
	}

	// start a shared agent service on a named pipe
	sharedAgent := ipc.NewSharedAgent(agent)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = ipc.StartNamedPipe(ctx, sew, sharedAgent, agent.ReleaseId)
	if err != nil {
		log.Error().Err(err).Msg("failed to start named pipe")
		return 1
	}

	// when all went well proceed to execute as a windows service
	err = svc.Run(SVC_NAME, &agentService{agent: sharedAgent, cancelPipeServer: cancel, svcReleaseId: agent.ReleaseId})
	if err != nil {
		log.Error().Msgf("%s service failed: %v", SVC_NAME, err)
		return 1
	}

	return 0
}
