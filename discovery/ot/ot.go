/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package ot implements operational technology protocol scanners including PROFINET, EtherCAT, and mDNS.
package ot

import (
	"fmt"
	"net"
	"strings"

	"github.com/siemens/GoScans/utils"
)

// Host represents a host discovered via L2/OT protocols.
type Host struct {
	MacAddress string
	Ip         string
	DnsName    string
	OsGuess    string
}

// Scanner defines the settings required by the OT discovery scan.
type Scanner struct {
	NetworkInterface string       // The network interface to run the OT scans on, e.g. "eth0"
	logger           utils.Logger // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
}

// NewScanner creates an OT discovery scanner for the given network interface.
// Returns an error if the interface name is empty or cannot be found on the host.
func NewScanner(logger utils.Logger, nwInterface string) (*Scanner, error) {

	// Check if network interface is provided
	if nwInterface == "" {
		return nil, fmt.Errorf("network interface is empty")
	}

	// Read local interfaces
	interfaces, errEnum := net.Interfaces()
	if errEnum != nil {
		return nil, fmt.Errorf("could not enumerate network interfaces: %w", errEnum)
	}

	// Check if provided network interface name exists
	found := false
	for _, iface := range interfaces {
		if iface.Name == nwInterface {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("network interface '%s' does not exist", nwInterface)
	}

	// Return OT discovery scanner
	return &Scanner{
		logger:           logger,
		NetworkInterface: nwInterface,
	}, nil
}

// Run runs all L2 OT discovery methods and collects results.
func (s *Scanner) Run() []Host {

	// Prepare memory for result data
	var allHosts []Host

	// PROFINET DCP Discovery
	s.logger.Infof("Executing discovery via PROFINET DCP on '%s'.", s.NetworkInterface)
	pnHosts, errPn := ScanProfinetDcp(s.logger, s.NetworkInterface)
	if errPn != nil {
		s.logger.Warningf("Could not execute discovery via PROFINET DCP: %s", errPn)
	} else {
		s.logger.Infof("Discovered %d devices via PROFINET DCP.", len(pnHosts))
		allHosts = append(allHosts, pnHosts...)
	}

	// EtherCAT Discovery
	s.logger.Infof("Executing discovery via EtherCAT on '%s'.", s.NetworkInterface)
	ecHosts, errEc := ScanEthercat(s.logger, s.NetworkInterface)
	if errEc != nil {
		s.logger.Warningf("Could not execute discovery via EtherCAT: %s", errEc)
	} else {
		s.logger.Infof("Discovered %d devices via EtherCAT.", len(ecHosts))
		allHosts = append(allHosts, ecHosts...)
	}

	// LLDP Passive Listening
	s.logger.Infof("Executing discovery via LLDP listener on '%s'.", s.NetworkInterface)
	lldpHosts, errLldp := ListenLldp(s.logger, s.NetworkInterface)
	if errLldp != nil {
		s.logger.Warningf("Could not execute discovery via LLDP listener: %s", errLldp)
	} else {
		s.logger.Infof("Discovered %d devices via LLDP listener.", len(lldpHosts))
		allHosts = append(allHosts, lldpHosts...)
	}

	// IPv6 Neighbor Discovery
	s.logger.Infof("Executing discovery via IPv6 NDP on '%s'.", s.NetworkInterface)
	ndpHosts, errNdp := ScanNdp(s.logger, s.NetworkInterface)
	if errNdp != nil {
		s.logger.Warningf("Could not execute discovery via IPv6 NDP: %s", errNdp)
	} else {
		s.logger.Infof("Discovered %d devices via IPv6 NDP.", len(ndpHosts))
		allHosts = append(allHosts, ndpHosts...)
	}

	// mDNS/SSDP Discovery
	s.logger.Infof("Executing discovery via mDNS/SSDP on '%s'.", s.NetworkInterface)
	mdnsHosts, errMdns := ScanMdnsSsdp(s.logger, s.NetworkInterface)
	if errMdns != nil {
		s.logger.Warningf("Could not execute discovery via mDNS/SSDP: %s", errMdns)
	} else {
		s.logger.Infof("Discovered %d devices via mDNS/SSDP.", len(mdnsHosts))
		allHosts = append(allHosts, mdnsHosts...)
	}

	// Return merged results
	return mergeByMac(allHosts)
}

// mergeByMac merges host details sharing the same MAC address, keeping the most-populated fields.
// Hosts without a MAC address are kept as-is.
func mergeByMac(hosts []Host) []Host {

	// Separate hosts with a known MAC from those without one
	macMap := make(map[string]Host)
	var noMac []Host

	// Classify and merge each host by its MAC key
	for _, h := range hosts {

		// Hosts without MAC cannot be deduplicated — keep them verbatim
		if h.MacAddress == "" {
			noMac = append(noMac, h)
			continue
		}

		// Merge with an existing entry or insert as new
		key := strings.ToUpper(h.MacAddress)
		if existing, ok := macMap[key]; ok {
			if existing.Ip == "" && h.Ip != "" {
				existing.Ip = h.Ip
			}
			if existing.DnsName == "" && h.DnsName != "" {
				existing.DnsName = h.DnsName
			}
			if existing.OsGuess == "" && h.OsGuess != "" {
				existing.OsGuess = h.OsGuess
			}
			macMap[key] = existing // Write merged result back; map lookup returns a copy for value types
		} else {
			macMap[key] = h
		}
	}

	// Combine no-MAC hosts with merged MAC-keyed hosts
	result := noMac
	for _, h := range macMap {
		result = append(result, h)
	}
	return result
}
