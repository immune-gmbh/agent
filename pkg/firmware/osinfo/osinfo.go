package osinfo

import (
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

// XXX the stuct filled by this function has inconsistent error reporting semantics
func ReportOSInfo(osInfo *api.OS) error {
	log.Trace().Msg("ReportOSInfo()")

	release, err := readOSReleasePrettyName()
	if err != nil {
		osInfo.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("osinfo.ReportOSInfo()")
		log.Warn().Msg("Failed to gather host informations")
		return err
	}
	osInfo.Release = release

	hostname, err := os.Hostname()
	if err != nil {
		osInfo.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("osinfo.ReportOSInfo()")
		log.Warn().Msg("Failed to gather host informations")
		return err
	}
	osInfo.Hostname = hostname

	return nil
}
