package common

import (
	"errors"

	"github.com/google/go-tpm/tpmutil/tbs"
)

// MapTBSErrors maps errors from windows TPM base services API
func MapTBSErrors(err error) error {
	var tbsError tbs.Error
	if errors.As(err, &tbsError) {
		if tbsError == tbs.ErrAccessDenied {
			return ErrorNoPermission(err)
		}
		if tbsError == tbs.ErrTPMNotFound || tbsError == tbs.ErrServiceDisabled || tbsError == tbs.ErrNoEventLog {
			return ErrorNoResponse(err)
		}
	}
	return err
}
