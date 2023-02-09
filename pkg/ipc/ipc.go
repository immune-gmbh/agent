package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/immune-gmbh/agent/v3/pkg/core"
	"github.com/rs/zerolog"
)

const (
	// client-to-server commands
	CmdEnroll = "enroll"
	CmdAttest = "attest"
	CmdSetLog = "setLog"

	// server-to-client commands
	CmdEnrollReply = "enrollReply"
	CmdAttestReply = "attestReply"
	CmdLog         = "log"
	CmdHello       = "hello"
	CmdBusy        = "busy"
)

const defaultReadTimeout = 5 * time.Second

var (
	ErrProtocol = errors.New("protocol error")
	ErrBusy     = errors.New("server busy") // can not grant exclusive access for requested command right now
)

// AgentServiceStatus is atomically updated when an op begins or ends
// when an op begins the op name is set, last result is cleared and running is set to true
// when an op ends the result is set and op running is set to false
type AgentServiceStatus struct {
	Enrolled      bool       `json:"enrolled"`
	OpRunning     bool       `json:"op_running"`
	LastOperation string     `json:"last_op,omitempty"`
	LastResult    string     `json:"last_result,omitempty"`
	LastRun       *time.Time `json:"last_run,omitempty"`
}

type Message struct {
	Command string          `json:"cmd"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// CmdArgsHello tells connecting clients the protocol version, server release id and status
type CmdArgsHello struct {
	ProtocolVersion int                `json:"version"`
	BuildId         string             `json:"build"`
	Status          AgentServiceStatus `json:"status"`
}

// CmdArgsSetLog configures the server-to-client logger
type CmdArgsSetLog struct {
	LogLevel zerolog.Level `json:"log_level"`
}

// CmdArgsEnroll wraps cli arguments for enrollment command
type CmdArgsEnroll struct {
	Server   *url.URL `json:"server,omitempty"`
	Token    string   `json:"token"`
	DummyTPM bool     `json:"dummy_tpm"`
	TPMPath  string   `json:"tpm_path,omitempty"`
}

// CmdArgsEnrollReply wraps enrollment return values
type CmdArgsEnrollReply struct {
	Status string `json:"status,omitempty"`
}

// CmdArgsAttest wraps cli arguments for attest command
type CmdArgsAttest struct {
	DryRun bool `json:"dry_run"`
}

// CmdArgsAttestReply wraps attestation return values
// in the future this can be extended with a report dump and the SaaS' response
type CmdArgsAttestReply struct {
	Status string `json:"status,omitempty"`
}

type SharedAgentResource struct {
	serveExclusiveLock sync.Mutex
	agent              *core.AttestationClient
	status             AgentServiceStatus
}

func NewSharedAgent(agent *core.AttestationClient) *SharedAgentResource {
	s := SharedAgentResource{agent: agent}
	s.status.Enrolled = agent.State.IsEnrolled()
	return &s
}

func (a *SharedAgentResource) tryLock() bool {
	a.serveExclusiveLock.Lock()
	defer a.serveExclusiveLock.Unlock()
	if a.status.OpRunning {
		return false
	}
	a.status.OpRunning = true
	return true
}

func (a *SharedAgentResource) unlock(newOp, newResult string) {
	a.serveExclusiveLock.Lock()
	defer a.serveExclusiveLock.Unlock()
	a.status.OpRunning = false
	a.status.LastOperation = newOp
	a.status.LastResult = newResult
	now := time.Now()
	a.status.LastRun = &now
	a.status.Enrolled = a.agent.State.IsEnrolled()
}

// TryEnroll tries to get exclusive access to a shared agent to run the enroll operation
// if logger argument is not nil it will be used for logging during the operation
// returns false if exclusive access was not possible
func (a *SharedAgentResource) TryEnroll(ctx context.Context, logger *zerolog.Logger, arguments *CmdArgsEnroll) (bool, error) {
	var err error
	if !a.tryLock() {
		return false, nil
	}
	defer func() {
		s := ""
		if err != nil {
			s = err.Error()
		}
		a.unlock(CmdEnroll, s)
	}()

	// strap-in log; this is possible because we run all commands synchronously
	if logger != nil {
		oldLog := a.agent.Log
		a.agent.Log = logger
		defer func() {
			a.agent.Log = oldLog
		}()
	}

	err = a.agent.Enroll(ctx, arguments.Token, arguments.DummyTPM, arguments.TPMPath)
	return true, err
}

// TryAttest tries to get exclusive access to a shared agent to run the attest operation
// if logger argument is not nil it will be used for logging during the operation
// returns false if exclusive access was not possible
func (a *SharedAgentResource) TryAttest(ctx context.Context, logger *zerolog.Logger, arguments *CmdArgsAttest) (bool, error) {
	var err error
	if !a.tryLock() {
		return false, nil
	}
	defer func() {
		s := ""
		if err != nil {
			s = err.Error()
		}
		a.unlock(CmdAttest, s)
	}()

	// strap-in log; this is possible because we run all commands synchronously
	if logger != nil {
		oldLog := a.agent.Log
		a.agent.Log = logger
		defer func() {
			a.agent.Log = oldLog
		}()
	}

	_, err = a.agent.Attest(ctx, arguments.DryRun)
	return true, err
}

func (a *SharedAgentResource) Status() AgentServiceStatus {
	a.serveExclusiveLock.Lock()
	defer a.serveExclusiveLock.Unlock()
	return a.status
}

func writeMessageNext(w io.Writer, msg *Message) error {
	buf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	if _, err = w.Write(append([]byte{byte(',')}, buf...)); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

func writeMessageFirst(w io.Writer, msg *Message) error {
	buf, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	return nil
}

func readMessage(dec *json.Decoder) (*Message, error) {
	var m Message
	err := dec.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return &m, nil
}

func writeMessageStreamOpen(w io.Writer) error {
	if _, err := w.Write([]byte("[")); err != nil {
		return fmt.Errorf("message stream open: %w", err)
	}
	return nil
}

func writeMessageStreamClose(w io.Writer) error {
	if _, err := w.Write([]byte("]")); err != nil {
		return fmt.Errorf("message stream close: %w", err)
	}
	return nil
}

func expectDelimiter(dec *json.Decoder, token json.Delim) error {
	if t, err := dec.Token(); err != nil {
		return err
	} else if t != token {
		return fmt.Errorf("unexpected token got %s want %s", t, token)
	}
	return nil
}

func parseMessageStreamOpen(dec *json.Decoder) error {
	if err := expectDelimiter(dec, '['); err != nil {
		return fmt.Errorf("message stream open: %w", err)
	}
	return nil
}

func parseMessageStreamClose(dec *json.Decoder) error {
	if err := expectDelimiter(dec, ']'); err != nil {
		return fmt.Errorf("message stream close: %w", err)
	}
	return nil
}
