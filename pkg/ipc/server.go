package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// allocate static busy message once
var msgBusy = Message{Command: CmdBusy}

func doEnroll(ctx context.Context, logger *zerolog.Logger, agentResource *SharedAgentResource, arguments *CmdArgsEnroll) *Message {
	var replyArgs CmdArgsEnrollReply
	exclusive, err := agentResource.TryEnroll(ctx, logger, arguments)
	if err != nil {
		logger.Debug().Err(err).Msg("agentResource.TryEnroll(..)")
		replyArgs.Status = err.Error()
	}

	// another user is using the agent exclusively
	if !exclusive {
		return &msgBusy
	}

	buf, err := json.Marshal(&replyArgs)
	if err != nil {
		logger.Debug().Err(err).Msg("couldn't marshal reply args")
		buf = nil
	}
	return &Message{Command: CmdEnrollReply, Data: buf}
}

func doAttest(ctx context.Context, logger *zerolog.Logger, agentResource *SharedAgentResource, arguments *CmdArgsAttest) *Message {
	var replyArgs CmdArgsAttestReply
	exclusive, err := agentResource.TryAttest(ctx, logger, arguments)
	if err != nil {
		logger.Debug().Err(err).Msg("ac.Attest(..)")
		replyArgs.Status = err.Error()
	}

	// another user is using the agent exclusively
	if !exclusive {
		return &msgBusy
	}

	buf, err := json.Marshal(&replyArgs)
	if err != nil {
		logger.Debug().Err(err).Msg("couldn't marshal reply args")
		buf = nil
	}
	return &Message{Command: CmdAttestReply, Data: buf}
}

func parseClientMessages(ctx context.Context, conn net.Conn, logger *zerolog.Logger, stdLogOut io.Writer, agentResource *SharedAgentResource) error {
	dec := json.NewDecoder(conn)
	conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	if err := parseMessageStreamOpen(dec); err != nil {
		return err
	}

	// get a shared logger that sends log output over IPC and to local standard log output
	// both logs will use the server's level at first, but some commands may change the level
	// that is seen on IPC log outputs
	ilw := &ipcLogWriter{messageSink: conn}
	sharedLogger := GetSharedLog(logger, stdLogOut, ilw, logger.GetLevel(), logger.GetLevel())

	// messaging main loop
	// set a read deadline for each packet to drop clients that are just lingering around
	terminate := false
	conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	for !terminate && dec.More() {
		m, err := readMessage(dec)
		if err != nil {
			sharedLogger.Warn().Err(err).Msg("")
		}
		conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))

		var reply *Message
		switch m.Command {
		case CmdEnroll:
			var args CmdArgsEnroll
			if err := json.Unmarshal(m.Data, &args); err != nil {
				terminate = true
				sharedLogger.Warn().Msg("failed to parse enroll message")
			} else {
				reply = doEnroll(ctx, sharedLogger, agentResource, &args)
			}

		case CmdAttest:
			var args CmdArgsAttest
			if err := json.Unmarshal(m.Data, &args); err != nil {
				terminate = true
				sharedLogger.Warn().Msg("failed to parse attest message")
			} else {
				reply = doAttest(ctx, sharedLogger, agentResource, &args)
			}

		case CmdSetLog:
			var args CmdArgsSetLog
			if err := json.Unmarshal(m.Data, &args); err != nil {
				terminate = true
				sharedLogger.Warn().Msg("failed to parse setLog message")
			}

			// get a new logger with a different level on IPC
			sharedLogger = GetSharedLog(logger, stdLogOut, ilw, logger.GetLevel(), args.LogLevel)

		default:
			terminate = true
			sharedLogger.Warn().Msg("unknown message command")
		}

		// send out a reply if we have one
		if reply != nil {
			err = writeMessageNext(conn, reply)
			if err != nil {
				return err
			}
		}
	}

	// don't try to read anymore when terminating; we possibly can't passing anything after protocol errors
	if terminate {
		return ErrProtocol
	}

	conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	return parseMessageStreamClose(dec)
}

func writeHelloMessage(conn net.Conn, status AgentServiceStatus, serviceBuildId *string) error {
	helloArgs := CmdArgsHello{
		ProtocolVersion: 1,
		BuildId:         *serviceBuildId,
		Status:          status,
	}
	buf, err := json.Marshal(&helloArgs)
	if err != nil {
		return err
	}

	err = writeMessageFirst(conn, &Message{Command: CmdHello, Data: buf})
	if err != nil {
		return err
	}

	return nil
}

type timeoutIf interface {
	Timeout() bool
}

// handleClientConnection implements the server-side IPC protocol on an open client connection
func handleClientConnection(ctx context.Context, conn net.Conn, stdLogOut io.Writer, agentResource *SharedAgentResource, serviceBuildId *string) {
	defer conn.Close()

	// create a sub-logger for each client connection
	cl := log.Logger.With().Str("client", fmt.Sprint(conn.(fdInterface).Fd())).Logger() // XXX hacky client id
	cl.Info().Msg("accepted")
	defer cl.Info().Msg("disconnected")

	// let another go-routine abort the connection when the context has been canceled
	doneChan := make(chan int)
	defer close(doneChan)
	go func(ctx context.Context, ch chan int) {
		select {
		case <-ctx.Done():
			// this will abort all reads and writes
			conn.Close()

		case <-ch:
		}
	}(ctx, doneChan)

	// open an array, all our messages will be objects in an array
	err := writeMessageStreamOpen(conn)
	if err != nil {
		cl.Error().Err(err).Msg("")
		return
	}

	err = writeHelloMessage(conn, agentResource.Status(), serviceBuildId)
	if err != nil {
		cl.Error().Err(err).Msg("write hello message")
		return
	}

	err = parseClientMessages(ctx, conn, &cl, stdLogOut, agentResource)
	if err != nil {
		if errIsEof(err) {
			return
		}
		var te timeoutIf
		if errors.As(err, &te) && te.Timeout() {
			cl.Info().Msg("timed out")
		} else {
			cl.Error().Err(err).Msg("parse client messages")
		}
	}

	// close array (this is superficial in case client ended procotol)
	if err := writeMessageStreamClose(conn); err != nil {
		// if we can't write close anymore because the conn is closed than be it so
		if errIsEof(err) {
			return
		}
		cl.Error().Err(err).Msg("")
	}
}

type fdInterface interface {
	Fd() uintptr
}

type acceptResponse struct {
	conn net.Conn
	err  error
}

// serveAgent accepts agent client connections in goroutines; it will close the listener when exiting the listening thread
func serveAgent(ctx context.Context, l net.Listener, stdLogOut io.Writer, agentResource *SharedAgentResource, serviceBuildId *string) error {
	acceptCh := make(chan acceptResponse)

	// launch accept in a goroutine to be able to call close from here
	go func(l net.Listener, ch chan acceptResponse) {
		for {
			client, err := l.Accept()
			ch <- acceptResponse{client, err}
			if err != nil {
				close(ch)
				return
			}
		}
	}(l, acceptCh)

	// either get accepted clients or abort when the context has been canceled
	go func() {
		// this will synchronously abort the listener's accept
		defer l.Close()
		for {
			select {
			case <-ctx.Done():
				log.Debug().Err(ctx.Err()).Msg("serveAgent")
				return

			case response := <-acceptCh:
				err := response.err
				if err != nil {
					log.Error().Err(err).Msg("accepting client")
					return
				}

				go handleClientConnection(ctx, response.conn, stdLogOut, agentResource, serviceBuildId)
			}
		}
	}()

	return nil
}
