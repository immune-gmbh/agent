package heci

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	hostCircularWriteWindow = 0x00
	hostCtrlOffset          = 0x04
	meiCircularReadWindow   = 0x08
	meiCtrlOffset           = 0x0c
	maxMappedMem            = 8192
	heciTimeoutMs           = 500
	heciRetries             = 3
	heciInitTimeout         = 20
)

type Ctrl struct {
	Status     uint8
	Reader     int8
	Writer     int8
	BufferSize uint8
}

type heci struct {
	fd   *os.File
	data []byte
	mei  Ctrl
	host Ctrl
}

func (c *Ctrl) SetIRQEnable() {
	c.Status |= (1 << 0)
}

func (c *Ctrl) ClrIRQEnable() {
	c.Status &^= (1 << 0)
}

func (c *Ctrl) SetIRQStatus() {
	c.Status |= (1 << 1)
}

func (c *Ctrl) IsIRQStatus() bool {
	return (c.Status>>1)&1 != 0
}

func (c *Ctrl) ClrReset() {
	c.Status &^= (1 << 4)
}

func (c *Ctrl) SetReset() {
	c.Status |= (1 << 4)
}

func (c *Ctrl) IsReset() bool {
	return (c.Status>>4)&1 != 0
}

func (c *Ctrl) SetIRQTrigger() {
	c.Status |= (1 << 2)
}

func (c *Ctrl) IsIRQTrigger() bool {
	return (c.Status>>2)&1 != 0
}

func (c *Ctrl) SetReady() {
	c.Status |= (1 << 3)
}

func (c *Ctrl) IsReady() bool {
	return (c.Status>>3)&1 != 0
}

func (m *heci) readCtrl(offset uint32) error {
	data, err := m.readAt(offset)
	if err != nil {
		return err
	}
	var dst *Ctrl
	switch offset {
	case hostCtrlOffset:
		dst = &m.host
	case meiCtrlOffset:
		dst = &m.mei
	default:
		return fmt.Errorf("offset to read is unknown")
	}
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, data)
	reader := bytes.NewReader(tmp)
	if err := binary.Read(reader, binary.LittleEndian, dst); err != nil {
		return err
	}
	return nil
}

func (m *heci) writeCtrl(offset uint64) error {
	switch offset {
	case hostCtrlOffset:
	case meiCtrlOffset:
		return fmt.Errorf("can't write mei ctrl interface")
	default:
		return fmt.Errorf("offset to write is unknown")
	}
	err := m.writeAt8(m.host.Status, offset)
	if err != nil {
		return err
	}
	return nil
}

func (m *heci) writeAt32(src uint32, offset uint64) error {
	if (offset + 4) > maxMappedMem {
		return fmt.Errorf("data and offset exceed's mapped area")
	}
	ptr := unsafe.Pointer(&m.data[offset])
	*(*uint32)(ptr) = src
	return nil
}

func (m *heci) writeAt8(src uint8, offset uint64) error {
	if (offset) > maxMappedMem {
		return fmt.Errorf("data and offset exceed's mapped area")
	}
	ptr := unsafe.Pointer(&m.data[offset])
	*(*uint8)(ptr) = src
	return nil
}

func (m *heci) readAt(offset uint32) (val uint32, err error) {
	if offset >= maxMappedMem {
		return 0, fmt.Errorf("data and offset exceed's mapped area")
	}
	ptr := unsafe.Pointer(&m.data[offset])
	val = *(*uint32)(ptr)
	return
}

func (m *heci) waitMEReady(timeout100ms int) error {
	for i := 0; i < timeout100ms; i++ {
		if err := m.readCtrl(meiCtrlOffset); err != nil {
			return err
		}
		time.Sleep(time.Millisecond * 100)
		if m.mei.IsReady() {
			return nil
		}
	}

	return syscall.ETIMEDOUT
}

func (m *heci) init() error {
	m.host.ClrIRQEnable()
	m.host.SetReady()
	m.host.SetIRQTrigger()

	if err := m.readCtrl(meiCtrlOffset); err != nil {
		return err
	}
	if m.mei.IsReset() {
		m.host.SetReset()
		if err := m.writeCtrl(hostCtrlOffset); err != nil {
			return err
		}
	}

	if err := m.waitMEReady(heciInitTimeout); err != nil {
		return err
	}

	m.host.ClrReset()
	if err := m.writeCtrl(hostCtrlOffset); err != nil {
		return err
	}

	return nil
}

func (m *heci) reset() error {
	m.host.SetReset()
	m.host.SetIRQTrigger()
	if err := m.writeCtrl(hostCtrlOffset); err != nil {
		return err
	}
	if err := m.readCtrl(hostCtrlOffset); err != nil {
		return err
	}

	if err := m.waitMEReady(heciInitTimeout); err != nil {
		return err
	}

	m.host.SetReady()
	m.host.SetIRQTrigger()
	m.host.ClrReset()
	if err := m.writeCtrl(hostCtrlOffset); err != nil {
		return err
	}
	if err := m.readCtrl(hostCtrlOffset); err != nil {
		return err
	}
	return nil
}
