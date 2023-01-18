package heci

import (
	"errors"
	"strconv"
	"syscall"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

// ME variant register values
const (
	skuIgnition = iota
	skuTXE
	skuMEConsumer
	skuMEBusiness
	_
	skuLight
	skuSPS
)

// HECI PCI config space registers
const (
	heci1MMIOOffset = 0x10
	heci1Options    = 0x04
)

type MECommandIntf interface {
	runCommand(command []byte) ([]byte, error)
	close() error
}

func reportMEClientCommands(command *api.MEClientCommands) error {
	m, err := openMEClientInterface(command)
	if err != nil {
		return err
	}
	defer m.close()

	for i := range command.Commands {
		v := &command.Commands[i]
		var buf []byte
		buf, err := m.runCommand(v.Command)
		if err != nil {
			v.Error = common.ServeApiError(common.MapFSErrors(err))
			log.Trace().Msgf("heci.reportMEClientCommands(): cmd #%v %s", i, err.Error())
			continue
		}
		v.Response = buf
	}

	return nil
}

func ReportMECommands(commands []api.MEClientCommands) (err error) {
	log.Trace().Msg("ReportMECommands()")

	allFailed := true
	for i := range commands {
		v := &commands[i]
		err = reportMEClientCommands(v)
		allFailed = allFailed && err != nil
		if err != nil {
			v.Error = common.ServeApiError(common.MapFSErrors(err))
			log.Debug().Msgf("heci.ReportMECommands(): %s", err.Error())
		}
	}
	if allFailed && len(commands) > 0 {
		log.Warn().Msgf("Failed to contact Intel ME")
		return
	}

	err = nil
	return
}

// openMEClientInterface tries to open a HECI device or raw messaging via memory mapping as fallback
// Inside cmd parameter, GUID is required for the connection via device, the client address is required for raw messaging.
// If any is not supplied, then there will be no connection via that method.
// Address is expected to be < 0 if it is not present.
func openMEClientInterface(cmd *api.MEClientCommands) (MECommandIntf, error) {
	if cmd.GUID != nil {
		m, err := openMEI("", *cmd.GUID)
		if err != nil {
			// skip return if MEI can't be opened (path nonexistent) and raw HECI addr is specified
			var e syscall.Errno
			if !errors.As(err, &e) || !(e == syscall.ENOENT) || (len(cmd.Address) == 0) {
				return nil, err
			}
		} else {
			return m, nil
		}
	}

	if len(cmd.Address) != 0 {
		addr, err := strconv.ParseInt(cmd.Address, 10, 8)
		if err != nil {
			return nil, err
		}

		m, err := openHECI1(uint8(addr))
		if err != nil {
			return nil, err
		}

		// HECI requires init
		err = m.init()
		if err != nil {
			return nil, err
		}

		return m, nil
	}

	return nil, errors.New("neither GUID nor Address specified")
}
