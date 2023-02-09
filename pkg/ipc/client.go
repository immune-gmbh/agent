package ipc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// Client represents a once connected IPC client; all public methods are thread-safe
type Client struct {
	conn        net.Conn
	stdLogOut   io.Writer
	chClose     chan int
	chDone      chan int
	chSend      chan sendMsgRequest
	writeClosed *atomic.Bool
}

type readMsgResponse struct {
	msg *Message
	err error
}

type sendMsgRequest struct {
	msg   *Message
	wait  bool
	reply chan readMsgResponse
}

// newClient sets up a new client struct with a connection and is to be used by connection specific factory methods
func newClient(conn net.Conn, stdLogOut io.Writer) *Client {
	writeClosed := &atomic.Bool{}
	writeClosed.Store(false)
	return &Client{conn: conn, stdLogOut: stdLogOut, writeClosed: writeClosed, chClose: make(chan int), chDone: make(chan int), chSend: make(chan sendMsgRequest)}
}

// connectionSetup sets up our IPC protocol, starts a handler in a go-routine and returns the server's hello message upon success
// the underlying connection is never closed here, but it might be closed inside the handling thread (due to error or server sendling close)
func (cl *Client) connectionSetup() (*CmdArgsHello, error) {
	// prepare log config message arguments with current log level before going into stream protocol
	logCfg, err := json.Marshal(&CmdArgsSetLog{LogLevel: log.Logger.GetLevel()})
	if err != nil {
		return nil, fmt.Errorf("marshal setLog args: %w", err)
	}

	dec := json.NewDecoder(cl.conn)
	cl.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	err = parseMessageStreamOpen(dec)
	if err != nil {
		return nil, err
	}

	// open an array, all our messages will be objects in an array
	err = writeMessageStreamOpen(cl.conn)
	if err != nil {
		return nil, err
	}

	// expect a hello message as first message and write a log config message as response
	cl.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
	if dec.More() {
		cl.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		m, err := readMessage(dec)
		if err != nil {
			return nil, err
		}

		if m.Command != CmdHello {
			return nil, ErrProtocol
		}

		if err := writeMessageFirst(cl.conn, &Message{Command: CmdSetLog, Data: logCfg}); err != nil {
			return nil, err
		}

		var helloArgs CmdArgsHello
		if err := json.Unmarshal(m.Data, &helloArgs); err != nil {
			return nil, fmt.Errorf("unmarshal hello message args: %w", err)
		}
		if helloArgs.ProtocolVersion != 1 {
			log.Debug().Msg("unsupported protocol version")
			return nil, ErrProtocol
		}

		go cl.handleServerConnection(dec)

		return &helloArgs, nil
	} else {
		if err := writeMessageStreamClose(cl.conn); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
}

// Shutdown winds down the server and closes the underlying connection
func (cl *Client) Shutdown() {
	log.Debug().Msg("shutting down client")
	select {
	case cl.chClose <- 1:
		<-cl.chDone
	case <-cl.chDone:
	}
}

// sendMsg submits a message to be sent to the message handling goroutine and optionally waits for a reply
func (cl *Client) sendMsg(msg *Message, awaitReply bool) (*Message, error) {
	if cl.writeClosed.Load() {
		return nil, io.ErrClosedPipe
	}

	ch := make(chan readMsgResponse)
	defer close(ch)
	select {
	case <-cl.chDone:
		return nil, io.ErrClosedPipe
	case cl.chSend <- sendMsgRequest{msg: msg, reply: ch, wait: awaitReply}:
	}

	select {
	case reply := <-ch:
		if reply.err != nil {
			return nil, reply.err
		}
		return reply.msg, nil
	case <-cl.chDone:
		return nil, io.ErrClosedPipe
	}
}

// Enroll tries to enroll the remote attestation client with exclusive access
// returns ErrBusy when exclusive access fails
// when protocol is violated it will call Shutdown()
func (cl *Client) Enroll(args CmdArgsEnroll) (*CmdArgsEnrollReply, error) {
	data, err := json.Marshal(&args)
	if err != nil {
		return nil, fmt.Errorf("marshal enroll message args: %w", err)
	}
	reply, err := cl.sendMsg(&Message{Command: CmdEnroll, Data: data}, true)
	if err != nil {
		return nil, err
	}
	switch reply.Command {
	case CmdEnrollReply:
		var args CmdArgsEnrollReply
		if err := json.Unmarshal(reply.Data, &args); err != nil {
			return nil, fmt.Errorf("unmarshal enroll reply message args: %w", err)
		}
		return &args, nil

	case CmdBusy:
		return nil, ErrBusy

	default:
		log.Debug().Str("cmd", reply.Command).Msg("unexpected reply")
		cl.Shutdown()
		return nil, ErrProtocol
	}
}

// Attest tries to attest the remote attestation client with exclusive access
// returns ErrBusy when exclusive access fails
// when protocol is violated it will call Shutdown()
func (cl *Client) Attest(args CmdArgsAttest) (*CmdArgsAttestReply, error) {
	data, err := json.Marshal(&args)
	if err != nil {
		return nil, fmt.Errorf("marshal attest message args: %w", err)
	}
	reply, err := cl.sendMsg(&Message{Command: CmdAttest, Data: data}, true)
	if err != nil {
		return nil, err
	}
	switch reply.Command {
	case CmdAttestReply:
		var args CmdArgsAttestReply
		if err := json.Unmarshal(reply.Data, &args); err != nil {
			return nil, fmt.Errorf("unmarshal attest reply message args: %w", err)
		}
		return &args, nil

	case CmdBusy:
		return nil, ErrBusy

	default:
		log.Debug().Str("cmd", reply.Command).Msg("unexpected reply")
		cl.Shutdown()
		return nil, ErrProtocol
	}
}

// handleServerConnection runs in a goroutine and pumps messages between the server and this client's users
func (cl *Client) handleServerConnection(dec *json.Decoder) {
	// panic-safe cleanup
	defer func() {
		// send done and then close write msg channel to avoid senders racing with close
		close(cl.chDone)
		close(cl.chSend)
	}()
	defer cl.conn.Close()

	// launch a goroutine to receive messages
	readMsgChan := make(chan readMsgResponse)
	chSend := cl.chSend
	go func(dec *json.Decoder, ch chan readMsgResponse) {
		defer close(readMsgChan)
		// no deadline on dec.More(); wait indefinitely for the next ',' and then be impatient
		for dec.More() {
			cl.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
			m, err := readMessage(dec)
			readMsgChan <- readMsgResponse{m, err}
			if err != nil {
				return
			}
		}

		// exit gracefully
		cl.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		if err := parseMessageStreamClose(dec); err != nil {
			if !errIsEof(err) {
				log.Debug().Err(err).Msg("reader exit")
			}
		}
	}(dec, readMsgChan)

	var err error
	var replyChan chan readMsgResponse
	terminateWrite := false
loop:
	for {
		select {
		case <-cl.chClose:
			// when we get a close we immediately abort, dropping any messages being received or wanting to be written
			break loop

		case response, ok := <-readMsgChan:
			// the following blocks run when the reader is done
			if !ok {
				break loop
			}
			err = response.err
			if err != nil {
				if !errIsEof(err) {
					log.Error().Err(err).Msg("")
				}
				break loop
			}

			// either handle messages internally or pass on to a user handler if there is one
			if handled := cl.defaultServerMessageHandler(response.msg); !handled {
				// pass all non default messages to handler we got from send msg
				// if we have no handler then the protocol sequence is broken and we need to abort
				if replyChan != nil {
					select {
					case replyChan <- readMsgResponse{msg: response.msg}:
						// disable reply mode and re-enable message send channel
						replyChan = nil
						chSend = cl.chSend
					case <-cl.chClose:
						break loop
					}
				} else {
					log.Debug().Str("cmd", response.msg.Command).Msg("unhandled message")
					break loop
				}
			}

		case writeMsgReq := <-chSend:
			err = writeMessageNext(cl.conn, writeMsgReq.msg)
			if err != nil {
				writeMsgReq.reply <- readMsgResponse{err: err}
				terminateWrite = true
				break loop
			}

			// user wants to wait for a reply
			if writeMsgReq.wait {
				// store reply channel and disable chSend temporarily so further writers block
				replyChan = writeMsgReq.reply
				chSend = nil
			} else {
				writeMsgReq.reply <- readMsgResponse{}
			}

		}
	}

	cl.writeClosed.Store(true)
	log.Debug().Msg("closing connection")

	// write message stream close only if we had no EOF or write error
	if !errIsEof(err) && !terminateWrite {
		err := writeMessageStreamClose(cl.conn)
		if err != nil {
			log.Error().Err(err).Msg("")
		}
	}

	// terminate connection to make read goroutine return in all cases
	// be sure to exhaustively try-read channel to avoid a race where the server closes unexpectedly
	// while the reader goroutine is reading a message and Shutdown() has just been called between
	// the read message returning with eof and the error handling code trying to post the error
	// to the read channel
	cl.conn.Close()
	for range readMsgChan {
	}
}

// defaultServerMessageHandler processes messages that are handled by the server itself; other messages must be processed by the callers
func (cl *Client) defaultServerMessageHandler(msg *Message) bool {
	switch msg.Command {
	case CmdLog:
		_, err := io.Copy(cl.stdLogOut, bytes.NewReader(msg.Data))
		if err != nil {
			log.Warn().Err(err).Msg("recv remote log")
		}
	default:
		return false
	}

	return true
}
