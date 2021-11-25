package uefivars

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func hasUEFIVariables() bool {
	// We (wrongly) assume that every UEFI system has console output.
	_, err := readUEFIVariable("ConOut", "8be4df61-93ca-11d2-aa0d-00e098032b8c")
	return err == nil
}

func reportUEFIVariable(variable *api.UEFIVariable) error {
	val, err := readUEFIVariable(variable.Name, variable.Vendor)
	if err != nil {
		variable.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("uefivars.ReportUEFIVariable(): %s", err.Error())
		return err
	}

	buf := api.Buffer(val)
	variable.Value = &buf
	return nil
}

func ReportUEFIVariables(variables []api.UEFIVariable) (err error) {
	logrus.Traceln("ReportUEFIVariables()")

	if !hasUEFIVariables() {
		logrus.Warnln("UEFI variables not accessible")
		for i := range variables {
			v := &variables[i]
			v.Error = api.NotImplemented
		}
		return nil
	}

	allFailed := true
	for i := range variables {
		v := &variables[i]
		err = reportUEFIVariable(v)
		allFailed = allFailed && err != nil
	}
	if allFailed && len(variables) > 0 {
		logrus.Warnf("Failed to access UEFI variables")
		return
	}
	err = nil
	return
}
