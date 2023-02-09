//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The . specifies the local computer, but windows supports
// connecting to pipes on remote systems. The maximum length
// of this string is 256 characters.
const pipeGuardAgentSvc = `\\.\pipe\immuneGuardSvcV1`

/*
	MS says:

Named pipes can be used to provide communication between processes on the same computer or between processes on different computers across a network.
If the server service is running, all named pipes are accessible remotely.
If you intend to use a named pipe locally only, deny access to NT AUTHORITY\NETWORK or switch to local RPC.
-> the winio library sets FILE_PIPE_REJECT_REMOTE_CLIENTS on the pipe handle; max instances is set to 0xffffffff
*/
func StartNamedPipe(ctx context.Context, stdLogOut io.Writer, agentResource *SharedAgentResource, serviceBuildId *string) error {
	cfg := winio.PipeConfig{
		// see here https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
		// TLDR; it says 'The ACLs in the default security descriptor for a named pipe grant full control to the LocalSystem account, administrators, and the creator owner.'
		// what you see here are two ACE strings allowing bultin admins and disallowing network users (and thus RPC connections)
		SecurityDescriptor: "D:P(A;;GA;;;BA)(D;OICI;GA;;;NU)",

		// don't use message mode to keep the rest of the code compatible with character streams
		MessageMode: false,

		// 64k is enough for everyone
		InputBufferSize:  65536,
		OutputBufferSize: 65536,
	}

	l, err := winio.ListenPipe(pipeGuardAgentSvc, &cfg)
	if err != nil {
		return err
	}

	// hand our listener over to the generic serveAgent function
	err = serveAgent(ctx, l, stdLogOut, agentResource, serviceBuildId)
	if err != nil {
		return fmt.Errorf("agent IPC server: %w", err)
	}

	return nil
}

// ConnectNamedPipe attempts to connect to a server and returns a client that can be used to enroll or attest on the remote
// stdLogOut will receive zerolog structured log messages; use a console writer here for pretty printing
// may return io.EOF when the server closed the connection, ErrProtocol for unexpected procotol state transitions and timeout errors
func ConnectNamedPipe(ctx context.Context, stdLogOut io.Writer) (*Client, *CmdArgsHello, error) {
	conn, err := winio.DialPipeContext(ctx, pipeGuardAgentSvc)
	if err != nil {
		return nil, nil, err
	}

	cl := newClient(conn, stdLogOut)
	hello, err := cl.connectionSetup()
	if err != nil {
		conn.Close()
		if errIsEof(err) {
			err = io.EOF
		}
		return nil, nil, err
	}

	return cl, hello, nil
}

func errIsEof(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, winio.ErrFileClosed) || errors.Is(err, windows.ERROR_NO_DATA)
}
