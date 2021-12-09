// implement HECI using ME interface (mei) via official kernel drivers
package heci

import (
	"errors"
	"fmt"
	"syscall"

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

	if _, err = m.write(command); err != nil {
		return nil, fmt.Errorf("write to MEI failed: %w", err)
	}

	buf := make([]byte, m.maxMsgLength)

	// retry on timeout or EINTR, EAGAIN, etc
	// the mei interface returns with a zero-length read to indicate end-of-message
	for retry := 3; retry > 0; {
		var n int
		n, err = m.read(buf, 100)
		if err != nil {
			var tmpErr syscall.Errno
			if errors.As(err, &tmpErr) && tmpErr.Timeout() {
				retry--
				continue
			}
			return nil, fmt.Errorf("read from MEI failed: %w", err)
		}

		return buf[0:n], nil
	}
	return nil, fmt.Errorf("read from MEI timed out: %w", err)
}

// stop-gap for https://github.com/google/uuid/pull/75
func littleEndianUUID(guid uuid.UUID) [16]byte {
	u := [16]byte(guid)
	u[0], u[1], u[2], u[3] = u[3], u[2], u[1], u[0]
	u[4], u[5] = u[5], u[4]
	u[6], u[7] = u[7], u[6]
	return u
}
