package sev

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func reportSEVCommand(cmd *api.SEVCommand) error {
	val, err := runSEVCommand(cmd.Command, cmd.ReadLength)
	if err != nil {
		log.Debug().Err(err).Msg("sev.ReportSEVCommand()")
		cmd.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}

	buf := api.Buffer(val)
	cmd.Response = &buf
	return nil
}

func ReportSEVCommands(cmds []api.SEVCommand) (err error) {
	log.Trace().Msg("ReportSEVCommands()")

	allFailed := true
	for i := range cmds {
		v := &cmds[i]
		err = reportSEVCommand(v)
		allFailed = allFailed && err != nil
	}
	if allFailed && len(cmds) > 0 {
		log.Warn().Msg("Failed to access AMD SecureProcessor")
		return
	}

	err = nil
	return
}
