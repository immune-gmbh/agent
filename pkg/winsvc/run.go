//go:build windows

package winsvc

import (
	"context"
	"runtime"
	"time"

	"github.com/freman/eventloghook"
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/state"
	"github.com/immune-gmbh/agent/v3/pkg/util"
	"github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	SVC_NAME              = "immuneGuard"
	SVC_DESC              = "immune Guard Agent Service"
	defaultAttestInterval = time.Hour
)

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
	backoff *Exponential
	core    *core.AttestationClient
}

func (m *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	scheduleInterval := time.Millisecond
	m.backoff = &Exponential{Min: time.Minute, Max: defaultAttestInterval}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	log.Info().Msgf("immune Guard agent service %s (%s) started", *m.core.ReleaseId, runtime.GOARCH)

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
				break loop
			default:
				log.Error().Msgf("unexpected control request #%d", c)
			}
		}
	}
	return
}

func (m *agentService) runAttest() time.Duration {
	ctx := context.Background()

	// try to update our config for each attest we do
	// we could mostly encounter IO errors here but we should be able
	// to run attest anyway, so we just let UpdateConfig log the error
	m.core.UpdateConfig()

	// run attest and retry with exponential backoff in case of error
	_, _, err := m.core.Attest(ctx, "", false)
	if err != nil {
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
	logrus.AddHook(eventloghook.NewHook(elog))

	// bail out if not root
	root, err := util.IsRoot()
	if err != nil {
		log.Warn().Msg("Can't check user. It is recommended to run as administrator or root user")
		log.Debug().Msgf("util.IsRoot(): %s", err.Error())
	} else if !root {
		log.Error().Msg("This program must be run with elevated privileges")
		return 1
	}

	// init agent core
	agentCore := core.NewCore()
	if err := agentCore.Init(state.DefaultStateDir(), "", nil, &log.Logger); err != nil {
		return 1
	}

	if !agentCore.State.IsEnrolled() {
		log.Error().Msgf("No previous state found, please enroll first.")
		return 1
	}

	if err := agentCore.OpenTPM(); err != nil {
		return 1
	}

	err = svc.Run(SVC_NAME, &agentService{core: agentCore})
	if err != nil {
		log.Error().Msgf("%s service failed: %v", SVC_NAME, err)
		return 1
	}

	return 0
}
