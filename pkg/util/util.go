package util

import (
	"crypto/sha256"
	"io/ioutil"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

func Uint32ToStr(in uint32) string {
	return string([]uint8{uint8(in & 0xFF), uint8((in >> 8) & 0xFF), uint8((in >> 16) & 0xFF), uint8((in >> 24) & 0xFF)})
}

func SHA256File(file string) ([]byte, error) {
	h := sha256.New()
	s, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	h.Write(s)
	return h.Sum(nil), nil
}

func ZStdFile(file string) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	s, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return encoder.EncodeAll(s, make([]byte, 0, len(s))), nil
}

func FileToHashBlob(file string) api.HashBlob {
	digest, err := SHA256File(file)
	if err != nil {
		logrus.Debugf("util.SHA256File(): %s %s", file, err.Error())
		return api.HashBlob{Error: common.ServeApiError(common.MapFSErrors(err))}
	}

	zData, err := ZStdFile(file)
	if err != nil {
		logrus.Debugf("util.ZStdFile(): %s %s", file, err.Error())
		return api.HashBlob{Error: common.ServeApiError(common.MapFSErrors(err))}
	}

	return api.HashBlob{Sha256: digest, ZData: zData}
}
