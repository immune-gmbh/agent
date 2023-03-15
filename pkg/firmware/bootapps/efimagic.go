package bootapps

import (
	"encoding/binary"
	"io"
	"os"
)

// some 4-byte offset is located at byte 60-63 so it (excluding weird hacks) must point to at least 64
// from that offset we'll find a 2 byte value 24 bytes on, so we must at least have 64+25 bytes
const efiMinLen = 89

// readEfiFile will read file completely if it is an EFI application
// determining if the byte buffer contains an EFI image as defined here https://www.iana.org/assignments/media-types/application/efi
func readEfiFile(file *os.File) ([]byte, error) {
	st, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if st.Size() < efiMinLen {
		return nil, nil
	}

	buf := make([]byte, 65)
	_, err = file.Read(buf)
	if err != nil {
		return nil, err
	}

	if !(buf[0] == 'M' && buf[1] == 'Z') {
		return nil, nil
	}

	offset := binary.LittleEndian.Uint32(buf[60:64])
	if uint64(offset+25) < uint64(len(buf)) {
		return nil, nil
	}

	// at this point we need to read the whole file
	_, err = file.Seek(0, 0)
	if err != nil {
		return nil, err
	}
	buf, err = io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	val := binary.LittleEndian.Uint16(buf[offset+24 : offset+26])
	if !(buf[offset] == 'P' && buf[offset+1] == 'E' && (val == 0x010b || val == 0x020b)) {
		return nil, nil
	}

	return buf, nil
}
