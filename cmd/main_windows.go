//go:build windows

package main

import (
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/cli"
	"github.com/immune-gmbh/agent/v3/pkg/winsvc"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
)

func main() {
	os.Exit(run())
}

func run() int {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Error().Msg("failed to determine if agent is running as windows service")
		return 1
	}

	if isService {
		return winsvc.RunService()
	}

	// assume CLI identity if we are not a service
	return cli.RunCommandLineTool()
}
