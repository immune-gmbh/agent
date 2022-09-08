//go:build !windows

package epp

import "github.com/immune-gmbh/agent/v3/pkg/api"

func ReportEPP(eppInfo *api.EPPInfo) error {
	return nil
}
