package bootapps

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

func getBootAppMap(rootPath, mountPath string) (map[string]api.HashBlob, error) {
	var bootApps = make(map[string]api.HashBlob)
	rootPath = filepath.Clean(rootPath)
	mountPath = filepath.Clean(mountPath)
	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == rootPath {
				return err
			}
			log.Debug().Err(err).Str("path", path).Msg("bootapps.getBootAppMap() walk")
			return nil
		}

		if !d.IsDir() {
			f, err := os.OpenFile(path, os.O_RDONLY, 0)
			if err != nil {
				log.Debug().Err(err).Str("path", path).Msg("bootapps.getBootAppMap() open")
				return nil
			}

			buf, err := readEfiFile(f)
			if err != nil {
				log.Debug().Err(err).Str("path", path).Msg("bootapps.getBootAppMap() read")
				return nil
			}
			if buf == nil {
				return nil
			}

			// strip mount path prefix and only record relative path inside efi partition
			key, _ := strings.CutPrefix(path, mountPath)
			bootApps[key] = api.HashBlob{Data: buf}
		}

		return nil
	})

	if err != nil || len(bootApps) == 0 {
		return nil, err
	}

	return bootApps, nil
}

func ReportBootApps(request *api.BootApps) {
	path, err := getEfiSystemPartPath()
	if err != nil {
		log.Debug().Err(err).Msg("bootapps.ReportBootApps()")
		request.ImagesErr = common.ServeApiError(common.MapFSErrors(err))
		return
	}

	bootApps, err := getBootAppMap(path, path)
	if err != nil {
		log.Debug().Err(err).Msg("bootapps.ReportBootApps()")
		request.ImagesErr = common.ServeApiError(common.MapFSErrors(err))
		return
	}

	request.Images = bootApps
}
