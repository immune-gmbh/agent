package biosflash

import (
	"github.com/immune-gmbh/agent/v3/pkg/firmware/immunecpu"
)

func readBiosFlashMMap() (outBuf []byte, err error) {
	return immunecpu.ReadBiosFlashMMap()
}
