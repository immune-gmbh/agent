package epp

import (
	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/immune-gmbh/agent/v3/pkg/util"
	"github.com/sirupsen/logrus"
)

func ReportEPP(eppInfo *api.EPPInfo) error {
	logrus.Traceln("ReportEPP()")

	elamDrivers, err := ListElamDriverPaths()
	if err == nil {
		eppInfo.EarlyLaunchDrivers = make(map[string]api.HashBlob)
		for _, drv := range elamDrivers {
			eppInfo.EarlyLaunchDrivers[drv] = util.FileToHashBlob(drv)
		}
	} else {
		eppInfo.EarlyLaunchDriversErr = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("epp.ListElamDriverPaths(): %s", err.Error())
	}

	pplImages, err := ListPPLProcessImagePaths()
	if err == nil {
		eppInfo.AntimalwareProcesses = make(map[string]api.HashBlob)
		for _, drv := range pplImages {
			eppInfo.AntimalwareProcesses[drv] = util.FileToHashBlob(drv)
		}
	} else {
		eppInfo.AntimalwareProcessesErr = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("epp.ListPPLProcessImagePaths(): %s", err.Error())
	}

	return nil
}
