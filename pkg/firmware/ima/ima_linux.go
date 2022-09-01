package ima

import (
	"io/ioutil"
)

func readIMALog() ([]byte, error) {
	return ioutil.ReadFile("/sys/kernel/security/ima/binary_runtime_measurements")
}
