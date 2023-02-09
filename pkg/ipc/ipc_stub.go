//go:build !windows

package ipc

import (
	"context"
	"io"
)

func StartNamedPipe(ctx context.Context, stdLogOut io.Writer, agentResource *SharedAgentResource, serviceBuildId *string) error {
	return nil
}

func ConnectNamedPipe(ctx context.Context, stdLogOut io.Writer) (*Client, *CmdArgsHello, error) {
	return nil, nil, nil
}

func errIsEof(err error) bool {
	return false
}
