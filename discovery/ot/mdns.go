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
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siemens/GoScans/utils"
)

const (
	mdnsAddr          = "224.0.0.251:5353"
	ssdpAddr          = "239.255.255.250:1900"
	mdnsListenTimeout = 5 * time.Second
)

// ScanMdnsSsdp queries mDNS and SSDP multicast groups to discover devices on the given interface.
func ScanMdnsSsdp(logger utils.Logger, iface string) ([]Host, error) {

	// Resolve the interface's IPv4 address for binding the outgoing socket
	localIp, errIp := getInterfaceIpV4(iface)
	if errIp != nil {
		return nil, errIp
	}

	// Accumulate results from both sub-protocols
	var allHosts []Host

	// mDNS discovery
	mdnsHosts, errMdns := queryMdns(logger, localIp)
	if errMdns != nil {
		logger.Warningf("Could not execute mDNS discovery: %s", errMdns)
	} else {
		allHosts = append(allHosts, mdnsHosts...)
	}

	// SSDP discovery
	ssdpHosts, errSsdp := querySsdp(logger, localIp)
	if errSsdp != nil {
		logger.Warningf("Could not execute SSDP discovery: %s", errSsdp)
	} else {
		allHosts = append(allHosts, ssdpHosts...)
	}

	// Return nil as everything went fine
	return allHosts, nil
}

// getInterfaceIpV4 returns the first IPv4 address assigned to the named interface.
func getInterfaceIpV4(iface string) (net.IP, error) {

	// Look up the interface by name
	ifi, errIfi := net.InterfaceByName(iface)
	if errIfi != nil {
		return nil, fmt.Errorf("could not find interface '%s': %w", iface, errIfi)
	}

	// Iterate addresses and return the first IPv4 one
	addrs, errAddrs := ifi.Addrs()
	if errAddrs != nil {
		return nil, fmt.Errorf("could not get addresses for '%s': %w", iface, errAddrs)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipV4 := ipNet.IP.To4(); ipV4 != nil {
			return ipV4, nil
		}
	}

	// Return nil as everything went fine
	return nil, fmt.Errorf("no IPv4 address on interface '%s'", iface)
}

// queryMdns sends an mDNS service-discovery query and collects responders.
func queryMdns(logger utils.Logger, localIp net.IP) ([]Host, error) {

	// Resolve the mDNS multicast address and open a UDP socket bound to the local IP
	addr, errAddr := net.ResolveUDPAddr("udp4", mdnsAddr)
	if errAddr != nil {
		return nil, errAddr
	}

	// Open a UDP socket bound to the local interface address
	conn, errConn := net.ListenUDP("udp4", &net.UDPAddr{IP: localIp, Port: 0})
	if errConn != nil {
		return nil, errConn
	}
	defer func() { _ = conn.Close() }()

	// Send the mDNS PTR query for _services._dns-sd._udp.local
	query := buildMdnsQuery("_services._dns-sd._udp.local")
	_, errSend := conn.WriteToUDP(query, addr)
	if errSend != nil {
		logger.Debugf("Could not send mDNS query: %s", errSend)
	}

	// Collect unique responders until the read deadline fires
	var hosts []Host
	var seen = make(map[string]bool)
	_ = conn.SetReadDeadline(time.Now().Add(mdnsListenTimeout))

	// Receive loop: read UDP datagrams until the deadline fires
	buf := make([]byte, 1500)
	for {
		n, remote, errRead := conn.ReadFromUDP(buf)
		if errRead != nil {
			break
		}

		// Minimum DNS header is 12 bytes
		if n < 12 {
			continue
		}

		// Record each unique source IP once
		ip := remote.IP.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true

		// Decode the mDNS response name and build a Host record
		hostname := extractMdnsName(buf[:n])
		host := Host{
			Ip:      ip,
			DnsName: hostname,
			OsGuess: "mDNS Responder",
		}
		logger.Debugf("mDNS response from '%s': %s", ip, hostname)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// querySsdp sends an SSDP M-SEARCH request and collects responders.
func querySsdp(logger utils.Logger, localIp net.IP) ([]Host, error) {

	// Resolve the SSDP multicast address and open a UDP socket bound to the local IP
	addr, errAddr := net.ResolveUDPAddr("udp4", ssdpAddr)
	if errAddr != nil {
		return nil, errAddr
	}

	// Open a UDP socket bound to the local interface address
	conn, errConn := net.ListenUDP("udp4", &net.UDPAddr{IP: localIp, Port: 0})
	if errConn != nil {
		return nil, errConn
	}
	defer func() { _ = conn.Close() }()

	// Send the SSDP M-SEARCH request to the multicast group
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"
	_, errSend := conn.WriteToUDP([]byte(msearch), addr)
	if errSend != nil {
		logger.Debugf("Could not send SSDP M-SEARCH: %s", errSend)
	}

	// Collect unique responders until the read deadline fires
	var hosts []Host
	var seen = make(map[string]bool)
	_ = conn.SetReadDeadline(time.Now().Add(mdnsListenTimeout))

	// Receive loop: read UDP datagrams until the deadline fires
	buf := make([]byte, 1500)
	for {
		n, remote, errRead := conn.ReadFromUDP(buf)
		if errRead != nil {
			break
		}

		// Record each unique source IP once
		ip := remote.IP.String()
		if seen[ip] {
			continue
		}
		seen[ip] = true

		// Extract the SERVER header and build a Host record
		serverInfo := extractSsdpServer(string(buf[:n]))
		host := Host{
			Ip:      ip,
			OsGuess: serverInfo,
		}
		logger.Debugf("SSDP response from '%s': %s", ip, serverInfo)
		hosts = append(hosts, host)
	}

	// Return nil as everything went fine
	return hosts, nil
}

// buildMdnsQuery constructs a minimal mDNS/DNS-SD PTR query packet for the given name.
func buildMdnsQuery(name string) []byte {

	// Build a minimal DNS query packet for the given name
	var pkt []byte

	// DNS header: ID=0, Flags=0 (standard query), QD=1, AN/NS/AR=0
	pkt = append(pkt, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)

	// Encode the query name as DNS labels
	for _, part := range strings.Split(name, ".") {
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, []byte(part)...)
	}
	pkt = append(pkt, 0) // root label terminator

	// QTYPE=PTR (12), QCLASS=IN (1)
	pkt = append(pkt, 0, 12, 0, 1)

	// Return the completed DNS PTR query packet
	return pkt
}

// extractMdnsName decodes the name from the first answer record in an mDNS/DNS response packet.
func extractMdnsName(data []byte) string {

	// Require at least a 12-byte DNS header
	if len(data) < 12 {
		return ""
	}

	// Skip past the DNS header and any question records to reach the first answer
	offset := 12
	qdCount := int(data[4])<<8 | int(data[5])
	for i := 0; i < qdCount && offset < len(data); i++ {
		for offset < len(data) && data[offset] != 0 {
			if data[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(data[offset]) + 1
		}
		if offset < len(data) && data[offset] == 0 {
			offset++
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Bail out if question-record parsing consumed all available data
	if offset >= len(data) {
		return ""
	}

	// Decode and strip .local suffix from the answer name
	name := decodeDnsName(data, offset)
	name = strings.TrimSuffix(name, ".local.")
	name = strings.TrimSuffix(name, ".local")
	return name
}

// decodeDnsName iteratively decodes a DNS wire-format name starting at offset.
// It follows compression pointers and guards against infinite pointer cycles.
func decodeDnsName(data []byte, offset int) string {

	// Accumulate decoded labels; joined with "." on return
	var parts []string

	// Guard against pointer loops: each byte offset may be visited at most once
	visited := make(map[int]bool)

	// Iteratively decode labels and follow compression pointers
	for offset < len(data) {
		if visited[offset] {
			break // pointer cycle detected — terminate
		}
		visited[offset] = true

		// Read the next label length or compression-pointer marker
		length := int(data[offset])
		if length == 0 {
			break
		}

		// Follow a DNS compression pointer (top two bits set)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			offset = ptr // jump; continue the same loop rather than recursing
			continue
		}

		// Read a plain label
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	// Return the assembled domain name
	return strings.Join(parts, ".")
}

// extractSsdpServer extracts the value of the SERVER header from an SSDP response.
// Returns "SSDP Device" when no SERVER header is present.
func extractSsdpServer(response string) string {

	// Scan header lines for the SERVER field
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToUpper(line), "SERVER:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return "SSDP Device"
}
