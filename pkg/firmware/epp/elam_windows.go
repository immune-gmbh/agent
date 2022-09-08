package epp

import (
	"github.com/yusufpapurcu/wmi"
)

const elamQuery = "associators of {Win32_LoadOrderGroup.Name='Early-Launch'} where AssocClass = Win32_LoadOrderGroupServiceMembers ResultClass = Win32_SystemDriver"

// ListElamDriverPaths lists paths of driver files registered in the ELAM load order group
func ListElamDriverPaths() ([]string, error) {
	var elam []struct{ PathName string }
	err := wmi.Query(elamQuery, &elam)
	if err != nil {
		return nil, err
	}

	paths := make([]string, len(elam))
	for i := range elam {
		paths[i] = elam[i].PathName
	}

	return paths, nil
}
