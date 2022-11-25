package fwupd

import (
	"github.com/godbus/dbus/v5"
	"github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v3/pkg/api"
)

const (
	FWUPD_FEATURE_FLAG_CAN_REPORT uint64 = 1 << iota
	FWUPD_FEATURE_FLAG_DETACH_ACTION
	FWUPD_FEATURE_FLAG_UPDATE_ACTION
	FWUPD_FEATURE_FLAG_SWITCH_BRANCH
	FWUPD_FEATURE_FLAG_REQUESTS
	FWUPD_FEATURE_FLAG_FDE_WARNING
	FWUPD_FEATURE_FLAG_COMMUNITY_TEXT
	FWUPD_FEATURE_FLAG_SHOW_PROBLEMS
	FWUPD_FEATURE_FLAG_ALLOW_AUTHENTICATION
	FWUPD_FEATURE_FLAG_NONE uint64 = 0
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

	// set feature flags to influence list of returned devices and releases
	err = obj.Call("org.freedesktop.fwupd.SetFeatureFlags", 0,
		FWUPD_FEATURE_FLAG_CAN_REPORT|
			FWUPD_FEATURE_FLAG_DETACH_ACTION|
			FWUPD_FEATURE_FLAG_UPDATE_ACTION|
			FWUPD_FEATURE_FLAG_SWITCH_BRANCH|
			FWUPD_FEATURE_FLAG_FDE_WARNING|
			FWUPD_FEATURE_FLAG_COMMUNITY_TEXT|
			FWUPD_FEATURE_FLAG_SHOW_PROBLEMS).Err
	if err != nil {
		logrus.Debugf("fwupd.ReportFWUPD(): %s", err.Error())
		logrus.Warnf("Failed to set FWUPD feature flags")
		return err
	}

	var devices []map[string]dbus.Variant
	err = obj.Call("org.freedesktop.fwupd.GetDevices", 0).Store(&devices)
	if err != nil {
		logrus.Debugf("fwupd.ReportFWUPD(): %s", err.Error())
		logrus.Warnf("Failed to get FWUPD devices")
		return err
	}

	devs.Topology = make([]map[string]interface{}, len(devices))
	var deviceIds []string
	for i, dev := range devices {
		devs.Topology[i] = make(map[string]interface{})
		for k, v := range dev {
			tmp := v.Value()
			if id, ok := tmp.(string); ok && k == "DeviceId" {
				deviceIds = append(deviceIds, id)
			}
			devs.Topology[i][k] = tmp
		}
	}

	devs.Releases = make(map[string][]api.FWUPdReleaseInfo, len(devices))
	for _, val := range deviceIds {
		var releases []map[string]dbus.Variant
		err = obj.Call("org.freedesktop.fwupd.GetReleases", 0, val).Store(&releases)
		// there are errors for devices that have no releases, no version set etc and for
		// now we just ignore them and treat all errors as "no releases", which might be to inaccurate in the future
		if err != nil {
			logrus.Debugf("fwupd.ReportFWUPD(): GetReleases %s %s", val, err.Error())
		} else {
			devs.Releases[val] = make([]api.FWUPdReleaseInfo, len(releases))
			for i, release := range releases {
				devs.Releases[val][i] = make(api.FWUPdReleaseInfo, len(release))
				for k, v := range release {
					devs.Releases[val][i][k] = v.Value()
				}
			}
		}
	}

	return nil
}
