package acpi

import (
	"io"
	"os"
	"path"

	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

var (
	sysfsDir = "/sys/firmware/acpi/tables"
)

func readACPITables() (map[string][]byte, error) {
	files, err := os.ReadDir(sysfsDir)
	if err != nil {
		return nil, err
	}

	tables := make(map[string][]byte)
	completeFailure := true
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		path := path.Join(sysfsDir, f.Name())
		buf, err := readACPITableFile(path)
		if err != nil {
			log.Debug().Err(err).Msgf("getting acpi table: %s", f.Name())
			continue
		}
		completeFailure = false
		tables[f.Name()] = buf
	}

	if completeFailure {
		return nil, common.MapFSErrors(err)
	}

	return tables, nil
}

func readACPITableFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
