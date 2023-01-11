//go:build !windows

package main

import (
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/cli"
)

func main() {
	os.Exit(cli.RunCommandLineTool())
}
