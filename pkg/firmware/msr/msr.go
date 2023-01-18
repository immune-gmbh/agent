package msr

import (
	"fmt"
	"runtime"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/immune-gmbh/agent/v3/pkg/util"
	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/cpu"
)

func reportMSR(msr *api.MSR) error {
	cpu, err := cpu.Counts(false)
	if err != nil {
		return err
	}

	var values []uint64
	completeFailure := true
	for i := 0; i < cpu; i++ {
		var value uint64
		// -> if at least one readout works, there is no error
		value, err = readMSR(uint32(i), msr.MSR)
		if err != nil {
			log.Trace().Msgf("[MSR] couldn't read msr %x on core %d: %s", msr.MSR, i, err)
			continue
		}
		completeFailure = false
		values = append(values, value)
	}

	if completeFailure {
		return fmt.Errorf("couldn't read msr %x", msr.MSR)
	}

	msr.Values = values
	return nil
}

func ReportMSRs(MSRs []api.MSR) error {
	log.Trace().Msg("ReportMSRs()")

	completeFailure := true
	var err error
	for i := range MSRs {
		v := &MSRs[i]
		err = reportMSR(v)
		completeFailure = completeFailure && err != nil
		if err != nil {
			log.Debug().Err(err).Msg("msr")
			v.Error = common.ServeApiError(common.MapFSErrors(err))
		}
	}
	if completeFailure && len(MSRs) > 0 {
		log.Warn().Msg("Failed to access model specific registers")
		if runtime.GOOS == "linux" {
			loaded, err := util.IsKernelModuleLoaded("msr")
			if err != nil {
				log.Warn().Msgf("error checking if msr kernel module is loaded: %v", err.Error())
			} else if !loaded {
				log.Warn().Msg("msr kernel module is not loaded")
			}
		}
		return err
	}

	return nil
}
