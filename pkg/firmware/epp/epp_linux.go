package epp

import (
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
)

func ReportEPP(eppInfo *api.EPPInfo) error {
	_, err := os.Stat("/sys/module/eset_rtp/refcnt")
	if os.IsNotExist(err) {
		log.Tracef("eset_rtp module not loaded")
		return nil
	}

	enabled, err := ioutil.ReadFile("/sys/module/eset_rtp/settings/enable")
	if err != nil {
		log.Debugf("Reading settings/enable: %s", err.Error())
		return err
	}
	exclFiles, err := ioutil.ReadFile("/sys/module/eset_rtp/settings/excludes/files")
	if err != nil {
		log.Debugf("Reading settings/excludes/files: %s", err.Error())
		return err
	}
	exclProcs, err := ioutil.ReadFile("/sys/module/eset_rtp/settings/excludes/procs")
	if err != nil {
		log.Debugf("Reading settings/excludes/procs: %s", err.Error())
		return err
	}

	eppInfo.ESET = &api.ESETConfig{
		Enabled:           string(enabled),
		ExcludedFiles:     string(exclFiles),
		ExcludedProcesses: string(exclProcs),
	}

	return nil
}
