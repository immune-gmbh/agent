package txt

import (
	"os"

	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
)

const (
	txtPubSpaceFilePath = "/sys/kernel/txt_mmap/public_space"
	maxMappedMem        = 0x10000
	txtPublicRegionMmap = 0xFED30000
)

func readTXTPublicSpace() ([]byte, error) {
	f, err := os.Open(txtPubSpaceFilePath)
	if os.IsNotExist(err) {
		// we tried mmap() but that only returns 0xff
		f, err = os.Open(common.DefaultDevMemPath)
		if err != nil {
			return nil, err
		}
		_, err = f.Seek(txtPublicRegionMmap, os.SEEK_SET)
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	defer f.Close()

	space := make([]byte, maxMappedMem)
	_, err = f.Read(space)
	if err != nil {
		return nil, err
	}
	return space, nil
}
