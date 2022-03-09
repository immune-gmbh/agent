package txt

import "github.com/immune-gmbh/agent/v3/pkg/firmware/immunecpu"

func readTXTPublicSpace() ([]byte, error) {
	return immunecpu.ReadTxtPublicSpace()
}
