/*
Package netif lists NICs and their OS assigned addresses while trying to filter out virtual ones.

When retrieving MAC addresses it is using the ones that are currently assigned which means they
might have been changed from the ones assigned by the vendor. This is because not all OSes allow
to get the 'real' MAC and thus this package sticks to that to exhibit consistent behaviour.
*/
package netif

import (
	"net"
	"strings"

	"github.com/immune-gmbh/agent/v3/pkg/api"
	"github.com/immune-gmbh/agent/v3/pkg/firmware/common"
	"github.com/rs/zerolog/log"
)

// deprecated
func ReportMACAddresses(macs *api.MACAddresses) error {
	log.Trace().Msg("ReportMACAddresses()")

	m, err := readMACAddresses()
	if err != nil {
		// on Windows the WMI calls return their own errors which are
		// mostly of no interest and just map to err-unknown here
		macs.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("netif.ReportMACAddresses()")
		log.Warn().Msg("Failed to get MAC addresses")
		return err
	}

	// normalize hex strings from different OSes
	for i := range m {
		m[i] = strings.ToUpper(m[i])
	}

	macs.Addresses = m
	return nil
}

func ReportNICs(nics *api.NICList) error {
	log.Trace().Msg("ReportNICs()")

	// get MAC addresses of (hopefully) non-virtual NICs
	macs, err := readMACAddresses()
	if err != nil {
		// on Windows the WMI calls return their own errors which are
		// mostly of no interest and just map to err-unknown here
		nics.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("netif.ReportNICs()")
		log.Warn().Msg("Failed to get list of network cards")
		return err
	}

	for i := range macs {
		mac := strings.ToUpper(macs[i])
		var nic api.NIC
		nic.MAC = mac
		nics.List = append(nics.List, nic)
	}

	// use OS independent Go API to get IPs and names
	ifas, err := net.Interfaces()
	if err != nil {
		nics.Error = common.ServeApiError(common.MapFSErrors(err))
		log.Debug().Err(err).Msg("netif.ReportNICs()")
		log.Warn().Msg("Failed to get list of network cards")
		return err
	}

	nm := make(map[string]*api.NIC)
	for i := range nics.List {
		nic := &nics.List[i]
		nm[nic.MAC] = nic
	}

	for _, ifa := range ifas {
		nic, present := nm[strings.ToUpper(ifa.HardwareAddr.String())]
		if !present {
			continue
		}

		nic.Name = ifa.Name

		addrs, err := ifa.Addrs()
		if err != nil {
			nic.Error = api.UnknownError
			log.Debug().Err(err).Msg("netif.ReportNICs()")
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ip4 := ipnet.IP.To4(); ip4 != nil {
				nic.IPv4 = append(nic.IPv4, addr.String())
			} else if ip16 := ipnet.IP.To16(); ip16 != nil {
				nic.IPv6 = append(nic.IPv6, addr.String())
			}
		}
	}

	return nil
}
