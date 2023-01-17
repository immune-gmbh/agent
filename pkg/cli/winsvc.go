//go:build windows

package cli

import (
	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/immune-gmbh/agent/v3/pkg/winsvc"
	"github.com/sirupsen/logrus"
)

type cmdWinSvc struct {
	// Subcommands
	Install cmdWinSvcInstall `cmd:"" help:"Install agent as a windows service"`
	Remove  cmdWinSvcRemove  `cmd:"" help:"Remove agent service"`
}

type cmdWinSvcInstall struct{}

func (c *cmdWinSvcInstall) Run(glob *core.AttestationClient) error {
	err := winsvc.Install(winsvc.SVC_NAME, winsvc.SVC_DESC)
	if err != nil {
		logrus.Errorf("failed to install service: %v", err)
		return err
	}

	logrus.Infof("installed service %v", winsvc.SVC_NAME)
	return nil
}

type cmdWinSvcRemove struct{}

func (c *cmdWinSvcRemove) Run(glob *core.AttestationClient) error {
	err := winsvc.Remove(winsvc.SVC_NAME)
	if err != nil {
		logrus.Errorf("failed to remove service: %v", err)
		return err
	}

	logrus.Infof("removed service %v", winsvc.SVC_NAME)
	return nil
}
