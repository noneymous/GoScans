/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ot

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
)

const (
	lldpEtherType      = 0x88CC
	lldpListenDuration = 60 * time.Second // 2x LLDP default interval (30s)

	// LLDP TLV Types
	lldpTlvEnd       = 0
	lldpTlvChassisId = 1
	lldpTlvSysName   = 5
	lldpTlvSysDesc   = 6
	lldpTlvMgmtAddr  = 8
)

// ListenLldp passively listens for LLDP frames on the given interface.
func ListenLldp(logger utils.Logger, iface string) ([]Host, error) {

	// Open raw socket on the interface
	ifi, errIf := net.InterfaceByName(iface)
	if errIf != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIf)
	}

	// Bind an Ethernet raw socket for the LLDP EtherType on the found interface
	conn, errConn := openRawEthernetSocket(ifi, lldpEtherType)
	if errConn != nil {
		return nil, fmt.Errorf("could not open raw socket on '%s': %w", iface, errConn)
	}
	defer func() { _ = conn.Close() }()

	// Prepare working variables
	var hosts []Host
	var seen = make(map[string]bool)
	var deadline = time.Now().Add(lldpListenDuration)
	_ = conn.SetReadDeadline(deadline)

	// Listen for LLDP frames until the deadline, deduplicating by source MAC
	logger.Debugf("Listening for LLDP frames on '%s' for %s.", iface, lldpListenDuration)
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, errRead := conn.Read(buf)
		if errRead != nil {
			if netErr, ok := errRead.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}

		// Discard frames that are too short to contain an Ethernet header
		if n < 14 {
			continue
		}

		// Filter to LLDP EtherType only
		etherType := binary.BigEndian.Uint16(buf[12:14])
		if etherType != lldpEtherType {
			continue
		}

		// Parse the LLDP payload, skipping already-seen source MACs
		srcMac := strings.ToUpper(net.HardwareAddr(buf[6:12]).String())
		if seen[srcMac] {
			continue
		}
		seen[srcMac] = true

		// Parse the LLDP payload into a Host record and add it to the result set
		host := parseLldpFrame(buf[14:n], srcMac)
		if host != nil {
			logger.Debugf("LLDP frame from '%s': %s", srcMac, host.DnsName)
			hosts = append(hosts, *host)
		}
	}

	// Return nil as everything went fine
	return hosts, nil
}

// parseLldpFrame parses an LLDP payload and returns a Host populated with the extracted fields.
func parseLldpFrame(data []byte, srcMac string) *Host {

	// Initialize the host record with the source MAC; TLV parsing populates the rest
	host := &Host{
		MacAddress: srcMac,
	}

	// Iterate over TLVs until End TLV or data is exhausted
	offset := 0
	for offset+2 <= len(data) {

		// TLV header: upper 7 bits = type, lower 9 bits = length
		tlvHeader := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvType := int(tlvHeader >> 9)
		tlvLen := int(tlvHeader & 0x01FF)
		offset += 2

		// End TLV or truncated TLV terminates parsing
		if tlvType == lldpTlvEnd || offset+tlvLen > len(data) {
			break
		}

		// Slice the TLV value bytes for processing in the switch below
		tlvData := data[offset : offset+tlvLen]

		// Dispatch on TLV type to extract the relevant host fields
		switch tlvType {
		case lldpTlvChassisId:
			// Sub-type 4 = MAC address (7 bytes: sub-type + 6 MAC bytes)
			if len(tlvData) > 1 {
				subType := tlvData[0]
				if subType == 4 && len(tlvData) >= 7 {
					host.MacAddress = strings.ToUpper(net.HardwareAddr(tlvData[1:7]).String())
				}
			}

		case lldpTlvSysName:
			host.DnsName = strings.TrimRight(string(tlvData), "\x00")

		case lldpTlvSysDesc:
			host.OsGuess = strings.TrimRight(string(tlvData), "\x00")

		case lldpTlvMgmtAddr:
			// Management address: addrLen(1) + addrSubType(1) + addr(variable)
			// Sub-type 1 = IPv4 (4 bytes after the sub-type byte)
			if len(tlvData) >= 6 {
				addrSubType := tlvData[1]
				if addrSubType == 1 && len(tlvData) >= 6 {
					ip := net.IP(tlvData[2:6])
					if !ip.Equal(net.IPv4zero) {
						host.Ip = ip.String()
					}
				}
			}
		}

		offset += tlvLen // advance past this TLV's value bytes
	}

	// Return nil as everything went fine
	return host
}
