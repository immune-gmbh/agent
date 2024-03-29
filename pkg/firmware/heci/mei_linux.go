// Implement HECI using ME interface (mei) via official kernel drivers.
// The code is partially based on u-root code.
//
// Copyright 2020 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package heci

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type osHandleType *int

const (
	PATH_DEV_MEI         = "/dev/mei0"
	IOCTL_CONNECT_CLIENT = 0xC0104801
)

// openMEI connects to a specific ME client via HECI device
func openMEI(path string, clientGUID uuid.UUID) (*meiClient, error) {
	var m meiClient
	if path == "" {
		path = PATH_DEV_MEI
	}
	fd, err := syscall.Open(path, os.O_RDWR, 0755)
	if err != nil {
		return nil, err
	}
	log.Trace().Msgf("Connecting MEI client %v\n", clientGUID.String())
	data := littleEndianUUID(clientGUID)
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), IOCTL_CONNECT_CLIENT, uintptr(unsafe.Pointer(&data[0]))); err != 0 {
		return nil, fmt.Errorf("ioctl IOCTL_CONNECT_CLIENT failed: %w", err)
	}
	// can be racy, unless protected by a mutex
	m.handle = &fd

	// we expect at least 5 meaningful bytes to be returned, read them as per:
	// include/uapi/linux/mei.h
	m.maxMsgLength = binary.LittleEndian.Uint32(data[:4])
	m.protoVersion = int(uint8(data[4]))

	log.Trace().Msgf("Opened MEI: %#v", m)
	return &m, nil
}

func (m *meiClient) close() error {
	if m.handle != nil {
		err := syscall.Close(*m.handle)
		m.handle = nil
		return err
	}
	return nil
}

func (m *meiClient) write(p []byte) (int, error) {
	// use syscall.Write instead of m.fd.Write to avoid epoll
	return syscall.Write(*m.handle, p)
}

func (m *meiClient) read(p []byte, timeoutMs uint) (int, error) {
	var r syscall.FdSet
	fd := *m.handle
	r.Bits[fd/64] = 1 << (fd % 64)
	tv := syscall.NsecToTimeval(int64(time.Millisecond * time.Duration(timeoutMs)))

	// use a select for reading as seen in the official metee library
	// this should allow us to read messages < page_size in one go
	n, err := syscall.Select(int(fd+1), &r, nil, nil, &tv)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, syscall.ETIMEDOUT
	}

	// use syscall.Read instead of m.fd.Read to avoid epoll
	return syscall.Read(fd, p)
}
