//go:build !windows

package cli

import "github.com/alecthomas/kong"

func osSpecificCommands() []kong.Option {
	return []kong.Option{}
}
