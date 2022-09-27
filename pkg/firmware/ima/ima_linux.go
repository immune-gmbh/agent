package ima

import "os"

func readIMALog() ([]byte, error) {
	return os.ReadFile("/sys/kernel/security/ima/binary_runtime_measurements")
}
