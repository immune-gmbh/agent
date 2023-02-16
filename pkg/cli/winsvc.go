//go:build windows

package cli

import (
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/winsvc"
	"github.com/rs/zerolog/log"
)

type cmdWinSvc struct {
	// Subcommands
	Install cmdWinSvcInstall `cmd:"" help:"Install agent as a windows service"`
	Remove  cmdWinSvcRemove  `cmd:"" help:"Remove agent service"`
}

type cmdWinSvcInstall struct {
	Force bool `help:"Install service even if it is already installed" default:"false"`
}

func (c *cmdWinSvcInstall) Run(glob *core.AttestationClient) error {
	err := winsvc.Install(winsvc.SVC_NAME, winsvc.SVC_DESC, c.Force)
	if err != nil {
		log.Error().Msgf("failed to install service: %v", err)
		return err
	}

	log.Info().Msgf("installed service %v", winsvc.SVC_NAME)
	return nil
}

type cmdWinSvcRemove struct{}

func (c *cmdWinSvcRemove) Run(glob *core.AttestationClient) error {
	err := winsvc.Remove(winsvc.SVC_NAME)
	if err != nil {
		log.Error().Msgf("failed to remove service: %v", err)
		return err
	}

	log.Info().Msgf("removed service %v", winsvc.SVC_NAME)
	return nil
}
