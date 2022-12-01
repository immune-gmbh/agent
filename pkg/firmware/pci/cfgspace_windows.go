package pci

// readConfigSpace is just a wrapper to keep things consistent
func readConfigSpace(bus, device, function, offset, maxcount uint32) (outBuf []byte, err error) {
	// currently not implemented, trying to move functionality into non-pnp driver
	return nil, nil
}
