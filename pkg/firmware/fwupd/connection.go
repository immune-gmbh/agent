package fwupd

import (
	"github.com/godbus/dbus/v5"
	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
)

func ReportFWUPD(devs *api.Devices) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		logrus.Debugf("fwupd.ReportFWUPD(): %s", err.Error())
		logrus.Warnf("Failed to connect to FWUPD via DBUS")
		return err
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.fwupd", "/")
	v, err := obj.GetProperty("org.freedesktop.fwupd.DaemonVersion")
	if err != nil {
		logrus.Debugf("fwupd.ReportFWUPD(): %s", err.Error())
		logrus.Warnf("Failed to get FWUPD version info")
		return err
	}
	devs.FWUPdVersion = v.String()

	var devices []map[string]dbus.Variant
	err = obj.Call("org.freedesktop.fwupd.GetDevices", 0).Store(&devices)
	if err != nil {
		logrus.Debugf("fwupd.ReportFWUPD(): %s", err.Error())
		logrus.Warnf("Failed to get FWUPD devices")
		return err
	}

	devs.Topology = make([]map[string]interface{}, len(devices))
	for i, dev := range devices {
		devs.Topology[i] = make(map[string]interface{})
		for k, v := range dev {
			devs.Topology[i][k] = v.Value()
		}
	}

	return nil
}
