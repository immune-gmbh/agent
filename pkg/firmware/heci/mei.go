// implement HECI using ME interface (mei) via official kernel drivers
package heci

import (
	"fmt"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// meiClient describes an ME client connection via HECI device using OS specific (file) handle type
type meiClient struct {
	handle       osHandleType
	maxMsgLength uint32
	protoVersion int
}

func (m *meiClient) runCommand(command []byte) ([]byte, error) {
	var err error
	for i := 0; i < 3; i++ {
		if _, err = m.write(command); err != nil {
			return nil, fmt.Errorf("write to MEI failed: %w", err)
		}

		buf := make([]byte, m.maxMsgLength)
		n, err := m.read(buf)
		if err == syscall.EINTR {
			time.Sleep(time.Millisecond * 100 << i)
			continue
		}
		if err != nil {
			break
		}

		return buf[:n], nil
	}
	return nil, fmt.Errorf("read from MEI failed: %w", err)
}

// stop-gap for https://github.com/google/uuid/pull/75
func littleEndianUUID(guid uuid.UUID) [16]byte {
	u := [16]byte(guid)
	u[0], u[1], u[2], u[3] = u[3], u[2], u[1], u[0]
	u[4], u[5] = u[5], u[4]
	u[6], u[7] = u[7], u[6]
	return u
}
