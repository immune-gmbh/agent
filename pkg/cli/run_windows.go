//go:build windows

package cli

import "github.com/alecthomas/kong"

func osSpecificCommands() []kong.Option {
	return []kong.Option{kong.DynamicCommand("winsvc", "Manage agent windows service", "", &cmdWinSvc{}, "hidden:\"\"")}
}
