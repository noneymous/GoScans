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
	"net"
	"os"
	"strings"
	"testing"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the ot package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmp := os.MkdirTemp(".", "goscans-ot-test-*")
	if errTmp != nil {
		panic(errTmp)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}

// TestMergeByMac verifies that mergeByMac correctly merges host fields by MAC address.
func TestMergeByMac(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name      string
		input     []Host
		wantCount int
		wantMac   string
		wantIp    string
		wantDns   string
		wantOs    string
	}{
		{
			name:      "empty-input",
			input:     nil,
			wantCount: 0,
		},
		{
			name: "single-host",
			input: []Host{
				{MacAddress: "AA:BB:CC:DD:EE:FF", Ip: "192.0.2.1", DnsName: "host.domain.tld"},
			},
			wantCount: 1,
			wantMac:   "AA:BB:CC:DD:EE:FF",
			wantIp:    "192.0.2.1",
			wantDns:   "host.domain.tld",
		},
		{
			name: "hosts-without-mac-preserved",
			input: []Host{
				{MacAddress: "", Ip: "192.0.2.1"},
				{MacAddress: "", Ip: "192.0.2.2"},
			},
			wantCount: 2,
		},
		{
			name: "multi-source-merge-for-one-mac",
			input: []Host{
				{MacAddress: "AA:BB:CC:DD:EE:FF", Ip: "192.0.2.1"},
				{MacAddress: "AA:BB:CC:DD:EE:FF", DnsName: "host.domain.tld"},
				{MacAddress: "AA:BB:CC:DD:EE:FF", OsGuess: "vendor-device-01"},
			},
			wantCount: 1,
			wantMac:   "AA:BB:CC:DD:EE:FF",
			wantIp:    "192.0.2.1",
			wantDns:   "host.domain.tld",
			wantOs:    "vendor-device-01",
		},
		{
			name: "mac-case-insensitive",
			input: []Host{
				{MacAddress: "aa:bb:cc:dd:ee:ff", Ip: "192.0.2.1"},
				{MacAddress: "AA:BB:CC:DD:EE:FF", DnsName: "host.domain.tld"},
			},
			wantCount: 1,
			wantIp:    "192.0.2.1",
			wantDns:   "host.domain.tld",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeByMac(tt.input)

			// Verify result count
			if len(got) != tt.wantCount {
				t.Errorf("mergeByMac() len = %d, want %d", len(got), tt.wantCount)
				return
			}

			// Verify merged host fields when a specific outcome is expected
			if tt.wantMac == "" && tt.wantIp == "" && tt.wantDns == "" && tt.wantOs == "" {
				return
			}
			for _, h := range got {
				if h.MacAddress != "" {
					if tt.wantIp != "" && h.Ip != tt.wantIp {
						t.Errorf("mergeByMac() Ip = '%v', want '%v'", h.Ip, tt.wantIp)
					}
					if tt.wantDns != "" && h.DnsName != tt.wantDns {
						t.Errorf("mergeByMac() DnsName = '%v', want '%v'", h.DnsName, tt.wantDns)
					}
					if tt.wantOs != "" && h.OsGuess != tt.wantOs {
						t.Errorf("mergeByMac() OsGuess = '%v', want '%v'", h.OsGuess, tt.wantOs)
					}
				}
			}
		})
	}
}

// TestNewScanner_UnknownInterface_ErrorHasSingleQuotes verifies the error message does not
// double-quote the interface name (regression for the '%q' format-string bug).
func TestNewScanner_UnknownInterface_ErrorHasSingleQuotes(t *testing.T) {

	// Retrieve test settings
	testLogger := utils.NewTestLogger()

	// Attempt to create scanner for a non-existent interface
	_, errNew := NewScanner(testLogger, "nonexistent-iface-xyz")
	if errNew == nil {
		t.Skip("NewScanner() returned nil error — interface unexpectedly exists; skipping")
		return
	}

	// Verify the interface name is quoted with single quotes only
	errMsg := errNew.Error()
	if strings.Contains(errMsg, `'"`) {
		t.Errorf("NewScanner() error = '%v', must not contain double-quoted interface name", errMsg)
	}
	if !strings.Contains(errMsg, "nonexistent-iface-xyz") {
		t.Errorf("NewScanner() error = '%v', want it to contain interface name", errMsg)
	}
}

// TestParseDcpResponse verifies that parseDcpResponse correctly extracts device name and IP from DCP response frames.
func TestParseDcpResponse(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name      string
		data      []byte
		srcMac    string
		wantNil   bool
		wantDns   string
		wantIp    string
		wantOsHas string
	}{
		{
			name:      "too-short",
			data:      []byte{0xFE, 0xFF, 0x05, 0x01},
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   true,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "wrong-frameid",
			data:      []byte{0xFE, 0xFE, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   true,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "wrong-service-type",
			data:      []byte{0xFE, 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00},
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   true,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "valid-empty-response",
			data:      buildTestDcpResponse(nil, nil, nil),
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "valid-with-name",
			data:      buildTestDcpResponse([]byte("plc-station-1"), nil, nil),
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "plc-station-1",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "valid-with-ip",
			data:      buildTestDcpResponse(nil, []byte{192, 0, 2, 100, 255, 255, 255, 0, 0, 0, 0, 0}, nil),
			srcMac:    "00:0E:CF:12:34:56",
			wantNil:   false,
			wantDns:   "",
			wantIp:    "192.0.2.100",
			wantOsHas: "",
		},
		{
			name:      "ip-block-parsed",
			data:      buildTestDcpResponse([]byte("station-01"), []byte{198, 51, 100, 1, 255, 255, 255, 0, 0, 0, 0, 0}, nil),
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "station-01",
			wantIp:    "198.51.100.1",
			wantOsHas: "",
		},
		{
			name:      "vendor-sub-option",
			data:      buildTestDcpResponse(nil, nil, []byte("vendor-device-01")),
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "PROFINET",
		},
		{
			name:      "oversize-block-length",
			data:      buildTestDcpResponseOversizeBlock(),
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "",
			wantIp:    "",
			wantOsHas: "",
		},
		{
			name:      "odd-block-length-padding",
			data:      buildTestDcpResponse([]byte("odd"), nil, nil), // "odd" = 3 bytes, needs padding
			srcMac:    "AA:BB:CC:DD:EE:FF",
			wantNil:   false,
			wantDns:   "odd",
			wantIp:    "",
			wantOsHas: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDcpResponse(tt.data, tt.srcMac)
			if tt.wantNil {
				if got != nil {
					t.Errorf("parseDcpResponse() = '%v', want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("parseDcpResponse() = nil, want non-nil")
				return
			}
			if tt.wantDns != "" && got.DnsName != tt.wantDns {
				t.Errorf("parseDcpResponse() DnsName = '%v', want '%v'", got.DnsName, tt.wantDns)
			}
			if tt.wantIp != "" && got.Ip != tt.wantIp {
				t.Errorf("parseDcpResponse() Ip = '%v', want '%v'", got.Ip, tt.wantIp)
			}
			if tt.wantOsHas != "" && !strings.Contains(got.OsGuess, tt.wantOsHas) {
				t.Errorf("parseDcpResponse() OsGuess = '%v', want it to contain '%v'", got.OsGuess, tt.wantOsHas)
			}
		})
	}
}

// TestParseLldpFrame verifies that parseLldpFrame extracts system name and description from LLDP TLV frames.
func TestParseLldpFrame(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		data    []byte
		srcMac  string
		wantDns string
		wantOs  string
		wantIp  string
		wantMac string
	}{
		{
			name:    "empty",
			data:    []byte{},
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantDns: "",
			wantOs:  "",
		},
		{
			name:    "with-sysname",
			data:    buildTestLldpTlv(5, []byte("switch-core-01")),
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantDns: "switch-core-01",
			wantOs:  "",
		},
		{
			name:    "with-sysdesc",
			data:    buildTestLldpTlv(6, []byte("vendor-switch-v1.0")),
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantDns: "",
			wantOs:  "vendor-switch-v1.0",
		},
		{
			name:    "chassis-id-mac-sub-type",
			data:    buildTestLldpChassisIdMac([]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}),
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantMac: "00:1A:2B:3C:4D:5E",
		},
		{
			name:   "ipv4-management-address",
			data:   buildTestLldpMgmtAddrIpv4([]byte{192, 0, 2, 10}),
			srcMac: "AA:BB:CC:DD:EE:FF",
			wantIp: "192.0.2.10",
		},
		{
			name:    "malformed-tlv-too-short",
			data:    []byte{0x02}, // single byte TLV header — truncated
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantDns: "",
		},
		{
			name:    "tlv-length-exceeds-data",
			data:    buildTestLldpTlvRaw(5, 50, []byte("short")), // claims 50 bytes, provides 5
			srcMac:  "AA:BB:CC:DD:EE:FF",
			wantDns: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLldpFrame(tt.data, tt.srcMac)
			if got == nil {
				t.Errorf("parseLldpFrame() = nil, want non-nil")
				return
			}
			if tt.wantDns != "" && got.DnsName != tt.wantDns {
				t.Errorf("parseLldpFrame() DnsName = '%v', want '%v'", got.DnsName, tt.wantDns)
			}
			if tt.wantOs != "" && got.OsGuess != tt.wantOs {
				t.Errorf("parseLldpFrame() OsGuess = '%v', want '%v'", got.OsGuess, tt.wantOs)
			}
			if tt.wantIp != "" && got.Ip != tt.wantIp {
				t.Errorf("parseLldpFrame() Ip = '%v', want '%v'", got.Ip, tt.wantIp)
			}
			if tt.wantMac != "" && !strings.EqualFold(got.MacAddress, tt.wantMac) {
				t.Errorf("parseLldpFrame() MacAddress = '%v', want '%v'", got.MacAddress, tt.wantMac)
			}
		})
	}
}

// TestBuildDcpIdentifyFrame verifies that buildDcpIdentifyFrame produces a valid PROFINET DCP identify Ethernet frame.
func TestBuildDcpIdentifyFrame(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name   string
		srcMac []byte
	}{
		{
			name:   "standard-mac",
			srcMac: []byte{0x00, 0x0E, 0xCF, 0x01, 0x02, 0x03},
		},
		{
			name:   "all-zeros-mac",
			srcMac: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := buildDcpIdentifyFrame(tt.srcMac)

			// Verify minimum Ethernet frame size
			if len(frame) < 64 {
				t.Errorf("buildDcpIdentifyFrame() length = %d, want >= 64", len(frame))
			}

			// Verify destination MAC is PROFINET multicast
			if frame[0] != 0x01 || frame[1] != 0x0E || frame[2] != 0xCF {
				t.Errorf("buildDcpIdentifyFrame() dest MAC prefix = %X:%X:%X, want 01:0E:CF", frame[0], frame[1], frame[2])
			}

			// Verify EtherType is PROFINET
			if frame[12] != 0x88 || frame[13] != 0x92 {
				t.Errorf("buildDcpIdentifyFrame() EtherType = %02X%02X, want 8892", frame[12], frame[13])
			}

			// Verify source MAC is embedded at bytes 6–11
			for i, b := range tt.srcMac {
				if frame[6+i] != b {
					t.Errorf("buildDcpIdentifyFrame() srcMac[%d] = %02X, want %02X", i, frame[6+i], b)
				}
			}
		})
	}
}

// TestBuildEthercatBrdFrame verifies that buildEthercatBrdFrame produces a valid EtherCAT BRD frame.
func TestBuildEthercatBrdFrame(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name   string
		srcMac []byte
		ado    uint16
		length uint16
	}{
		{
			name:   "minimum-frame-length",
			srcMac: []byte{0x00, 0x0E, 0xCF, 0x01, 0x02, 0x03},
			ado:    0x0110,
			length: 2,
		},
		{
			name:   "zero-ado",
			srcMac: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			ado:    0x0000,
			length: 4,
		},
		{
			name:   "max-ado",
			srcMac: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			ado:    0xFFFF,
			length: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := buildEthercatBrdFrame(tt.srcMac, tt.ado, tt.length)

			// Verify minimum Ethernet frame size
			if len(frame) < 64 {
				t.Errorf("buildEthercatBrdFrame() length = %d, want >= 64", len(frame))
			}

			// Verify destination MAC is broadcast
			for i := 0; i < 6; i++ {
				if frame[i] != 0xFF {
					t.Errorf("buildEthercatBrdFrame() dest MAC[%d] = %02X, want FF", i, frame[i])
				}
			}

			// Verify EtherType is EtherCAT
			if frame[12] != 0x88 || frame[13] != 0xA4 {
				t.Errorf("buildEthercatBrdFrame() EtherType = %02X%02X, want 88A4", frame[12], frame[13])
			}

			// Verify ADO encoding at bytes 18–19 (after Ethernet header 14 + EtherCAT header 2 + cmd 1 + idx 1 + adp 2 = 20)
			gotAdo := uint16(frame[20]) | uint16(frame[21])<<8
			if gotAdo != tt.ado {
				t.Errorf("buildEthercatBrdFrame() ADO = %04X, want %04X", gotAdo, tt.ado)
			}

			// Verify BRD command byte at offset 16
			if frame[16] != ethercatBrdCommand {
				t.Errorf("buildEthercatBrdFrame() command = %02X, want %02X", frame[16], ethercatBrdCommand)
			}
		})
	}
}

// TestBuildMdnsQuery verifies that buildMdnsQuery constructs a valid DNS query packet for the given service name.
func TestBuildMdnsQuery(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name        string
		queryName   string
		wantQdCount int
	}{
		{
			name:        "service-discovery-name",
			queryName:   "_services._dns-sd._udp.local",
			wantQdCount: 1,
		},
		{
			name:        "simple-name",
			queryName:   "host.domain.tld",
			wantQdCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := buildMdnsQuery(tt.queryName)

			// Verify DNS header length
			if len(query) < 12 {
				t.Errorf("buildMdnsQuery() length = %d, want >= 12", len(query))
				return
			}

			// Verify QD count
			qdCount := int(query[4])<<8 | int(query[5])
			if qdCount != tt.wantQdCount {
				t.Errorf("buildMdnsQuery() QD count = %d, want %d", qdCount, tt.wantQdCount)
			}
		})
	}
}

// TestExtractMdnsName verifies that extractMdnsName decodes the answer name from an mDNS response.
func TestExtractMdnsName(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "empty-data",
			data: []byte{},
			want: "",
		},
		{
			name: "too-short",
			data: []byte{0x00, 0x00, 0x00},
			want: "",
		},
		{
			name: "no-answers",
			data: buildTestMdnsResponseNoAnswers(),
			want: "",
		},
		{
			name: "well-formed-answer",
			data: buildTestMdnsResponseWithName("mydevice"),
			want: "mydevice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMdnsName(tt.data)
			if got != tt.want {
				t.Errorf("extractMdnsName() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

// TestDecodeDnsName verifies that decodeDnsName correctly decodes DNS names including compression pointers.
func TestDecodeDnsName(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name   string
		data   []byte
		offset int
		want   string
	}{
		{
			name:   "simple-labels",
			data:   []byte{3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0},
			offset: 0,
			want:   "foo.bar",
		},
		{
			name:   "empty-root-label",
			data:   []byte{0},
			offset: 0,
			want:   "",
		},
		{
			name:   "offset-beyond-data",
			data:   []byte{3, 'f', 'o', 'o', 0},
			offset: 100,
			want:   "",
		},
		{
			name: "compression-pointer",
			// "host" at offset 0, then at offset 5 a pointer back to offset 0
			data:   append([]byte{4, 'h', 'o', 's', 't', 0}, 0xC0, 0x00),
			offset: 6,
			want:   "host",
		},
		{
			name: "infinite-pointer-loop-guard",
			// Two bytes pointing to each other: offset 0 → offset 2 → offset 0
			data:   []byte{0xC0, 0x02, 0xC0, 0x00},
			offset: 0,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeDnsName(tt.data, tt.offset)
			if got != tt.want {
				t.Errorf("decodeDnsName() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

// TestExtractSsdpServer verifies that extractSsdpServer extracts the SERVER header value from an SSDP response.
func TestExtractSsdpServer(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "with-server",
			response: "HTTP/1.1 200 OK\r\nSERVER: Linux/3.10 UPnP/1.0\r\n\r\n",
			want:     "Linux/3.10 UPnP/1.0",
		},
		{
			name:     "without-server",
			response: "HTTP/1.1 200 OK\r\n\r\n",
			want:     "SSDP Device",
		},
		{
			name:     "lowercase-server",
			response: "HTTP/1.1 200 OK\r\nserver: vendor-device-01/1.0\r\n\r\n",
			want:     "vendor-device-01/1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSsdpServer(tt.response)
			if got != tt.want {
				t.Errorf("extractSsdpServer() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

// buildTestDcpResponse constructs a minimal DCP response for testing.
func buildTestDcpResponse(nameOfStation []byte, ipParams []byte, vendor []byte) []byte {
	var data []byte

	// FrameID: DCP Identify Response
	data = append(data, 0xFE, 0xFF)

	// DCP Header
	data = append(data, 0x05, 0x01)             // ServiceID=Identify, ServiceType=Response
	data = append(data, 0x00, 0x00, 0x00, 0x01) // Xid
	data = append(data, 0x00, 0x04)             // ResponseDelay

	// Placeholder for DCPDataLength (filled below)
	dataLenPos := len(data)
	data = append(data, 0x00, 0x00)

	payloadStart := len(data)

	// NameOfStation block
	if nameOfStation != nil {
		blockData := append([]byte{0x00, 0x00}, nameOfStation...) // 2 bytes BlockInfo + value
		blockLen := len(blockData)
		data = append(data, dcpOptionDeviceProperties, dcpSubOptionNameOfStation)
		data = append(data, byte(blockLen>>8), byte(blockLen))
		data = append(data, blockData...)
		if blockLen%2 != 0 {
			data = append(data, 0x00) // Padding for odd block length
		}
	}

	// IP block
	if ipParams != nil {
		blockData := append([]byte{0x00, 0x00}, ipParams...) // 2 bytes BlockInfo + IP(4)+Subnet(4)+Gateway(4)
		blockLen := len(blockData)
		data = append(data, dcpOptionIp, dcpSubOptionIpParams)
		data = append(data, byte(blockLen>>8), byte(blockLen))
		data = append(data, blockData...)
		if blockLen%2 != 0 {
			data = append(data, 0x00)
		}
	}

	// Vendor block
	if vendor != nil {
		blockData := append([]byte{0x00, 0x00}, vendor...)
		blockLen := len(blockData)
		data = append(data, dcpOptionDeviceProperties, dcpSubOptionVendor)
		data = append(data, byte(blockLen>>8), byte(blockLen))
		data = append(data, blockData...)
		if blockLen%2 != 0 {
			data = append(data, 0x00)
		}
	}

	// Fill DCPDataLength
	payloadLen := len(data) - payloadStart
	data[dataLenPos] = byte(payloadLen >> 8)
	data[dataLenPos+1] = byte(payloadLen)

	return data
}

// buildTestDcpResponseOversizeBlock creates a DCP response where a block claims more data than available.
func buildTestDcpResponseOversizeBlock() []byte {
	var data []byte

	// FrameID + DCP header
	data = append(data, 0xFE, 0xFF)
	data = append(data, 0x05, 0x01)
	data = append(data, 0x00, 0x00, 0x00, 0x01)
	data = append(data, 0x00, 0x04)

	// DCPDataLength = 20 (claimed)
	data = append(data, 0x00, 0x14)

	// Block with blockLen = 100 (far exceeds remaining bytes)
	data = append(data, dcpOptionDeviceProperties, dcpSubOptionNameOfStation)
	data = append(data, 0x00, 0x64)           // blockLen = 100
	data = append(data, 0x00, 0x00, 'a', 'b') // only 4 bytes of data

	return data
}

// buildTestLldpTlv constructs a single LLDP TLV followed by an End TLV.
func buildTestLldpTlv(tlvType int, value []byte) []byte {
	var data []byte

	// TLV header: 7 bits type + 9 bits length
	header := uint16(tlvType<<9) | uint16(len(value))
	data = append(data, byte(header>>8), byte(header))
	data = append(data, value...)

	// End TLV
	data = append(data, 0x00, 0x00)

	return data
}

// buildTestLldpTlvRaw builds a TLV with an explicit length that may not match the value size.
func buildTestLldpTlvRaw(tlvType int, claimedLen int, value []byte) []byte {
	var data []byte

	// TLV header with claimed length (may differ from actual value size)
	header := uint16(tlvType<<9) | uint16(claimedLen)
	data = append(data, byte(header>>8), byte(header))
	data = append(data, value...)

	return data
}

// buildTestLldpChassisIdMac builds an LLDP Chassis ID TLV using the MAC address sub-type (4).
func buildTestLldpChassisIdMac(mac []byte) []byte {
	value := append([]byte{4}, mac...) // sub-type 4 = MAC address
	return buildTestLldpTlv(1, value)
}

// buildTestLldpMgmtAddrIpv4 builds an LLDP Management Address TLV for an IPv4 address.
func buildTestLldpMgmtAddrIpv4(ip []byte) []byte {
	// Management Address TLV: addrLen(1) + addrSubType(1) + addr(4) + ...
	value := append([]byte{
		0x05, // addrLen = 5 (1 sub-type byte + 4 IP bytes)
		0x01, // addrSubType = 1 (IPv4)
	}, ip...)
	return buildTestLldpTlv(8, value)
}

// buildTestMdnsResponseNoAnswers builds a minimal mDNS response with zero answer records.
func buildTestMdnsResponseNoAnswers() []byte {
	// DNS header: ID=0, Flags=0x8400 (response), QD=0, AN=0, NS=0, AR=0
	return []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// buildTestMdnsResponseWithName builds a minimal mDNS response packet containing the given name as the answer.
func buildTestMdnsResponseWithName(name string) []byte {
	var pkt []byte

	// DNS header: ID=0, Flags=0x8400 (response), QD=0, AN=1, NS=0, AR=0
	pkt = append(pkt, 0x00, 0x00, 0x84, 0x00)
	pkt = append(pkt, 0x00, 0x00)             // QD = 0
	pkt = append(pkt, 0x00, 0x01)             // AN = 1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00) // NS + AR = 0

	// Answer name: encoded label
	pkt = append(pkt, byte(len(name)))
	pkt = append(pkt, []byte(name)...)
	pkt = append(pkt, 0) // root label terminator

	// Answer TYPE=PTR(12), CLASS=IN(1), TTL=120, RDLENGTH=0
	pkt = append(pkt, 0x00, 0x0C, 0x00, 0x01)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x78) // TTL
	pkt = append(pkt, 0x00, 0x00)             // RDLENGTH = 0

	return pkt
}

// buildTestMdnsResponseWithQuestion builds a minimal mDNS response with one question and one answer.
// This exercises the question-skipping code path in extractMdnsName.
func buildTestMdnsResponseWithQuestion(name string) []byte {
	var pkt []byte

	// DNS header: QD=1, AN=1
	pkt = append(pkt, 0x00, 0x00, 0x84, 0x00)
	pkt = append(pkt, 0x00, 0x01) // QD = 1
	pkt = append(pkt, 0x00, 0x01) // AN = 1
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x00)

	// Question: label-encoded name + QTYPE + QCLASS
	pkt = append(pkt, byte(len(name)))
	pkt = append(pkt, []byte(name)...)
	pkt = append(pkt, 0)
	pkt = append(pkt, 0x00, 0x0C, 0x00, 0x01) // QTYPE=PTR, QCLASS=IN

	// Answer: same name again
	pkt = append(pkt, byte(len(name)))
	pkt = append(pkt, []byte(name)...)
	pkt = append(pkt, 0)
	pkt = append(pkt, 0x00, 0x0C, 0x00, 0x01)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x78) // TTL
	pkt = append(pkt, 0x00, 0x00)             // RDLENGTH = 0

	return pkt
}

// TestExtractMdnsName_WithQuestion exercises the question-record skipping path.
func TestExtractMdnsName_WithQuestion(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "one-question-one-answer",
			data: buildTestMdnsResponseWithQuestion("mydevice"),
			want: "mydevice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMdnsName(tt.data)
			if got != tt.want {
				t.Errorf("extractMdnsName() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}

// TestExtractNdpMac verifies that extractNdpMac correctly extracts the MAC from a Neighbor Advertisement.
func TestExtractNdpMac(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		buf     []byte
		wantMac string
	}{
		{
			name:    "too-short",
			buf:     make([]byte, 10),
			wantMac: "",
		},
		{
			name:    "no-options",
			buf:     make([]byte, 28),
			wantMac: "",
		},
		{
			name:    "with-target-link-layer-option",
			buf:     buildTestNdpAdvertisement([]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}),
			wantMac: "00:1A:2B:3C:4D:5E",
		},
		{
			name:    "option-type-not-two",
			buf:     buildTestNdpAdvertisementWrongOptionType([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}),
			wantMac: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNdpMac(tt.buf)
			if !strings.EqualFold(got, tt.wantMac) {
				t.Errorf("extractNdpMac() = '%v', want '%v'", got, tt.wantMac)
			}
		})
	}
}

// TestNewScanner_ValidInterface_ReturnsScanner verifies the happy path using the first available interface.
func TestNewScanner_ValidInterface_ReturnsScanner(t *testing.T) {

	// Find the first available network interface
	ifaces, errIfaces := net.Interfaces()
	if errIfaces != nil || len(ifaces) == 0 {
		t.Skip("no network interfaces available for scanner happy-path test")
		return
	}

	// Attempt to create a scanner
	testLogger := utils.NewTestLogger()
	scanner, errNew := NewScanner(testLogger, ifaces[0].Name)
	if errNew != nil {
		t.Skipf("could not create scanner for interface '%s': %v", ifaces[0].Name, errNew)
		return
	}
	if scanner == nil {
		t.Error("NewScanner() = nil, want non-nil scanner")
	}
}

// TestGetInterfaceIpV4_Loopback verifies that the loopback interface returns an IPv4 address.
func TestGetInterfaceIpV4_Loopback(t *testing.T) {

	// Attempt to get the loopback IPv4 address
	ip, errIp := getInterfaceIpV4("lo")
	if errIp != nil {
		t.Skipf("loopback interface not available: %v", errIp)
		return
	}

	// Verify the returned address is a valid IPv4
	if ip.To4() == nil {
		t.Errorf("getInterfaceIpV4() returned non-IPv4 address: '%v'", ip)
	}
}

// TestGetInterfaceIpV4_NonExistent verifies an error is returned for an unknown interface.
func TestGetInterfaceIpV4_NonExistent(t *testing.T) {

	// Attempt to get an address for an interface that does not exist
	_, errIp := getInterfaceIpV4("nonexistent-iface-xyz")
	if errIp == nil {
		t.Error("getInterfaceIpV4() expected error for non-existent interface, got nil")
	}
}

// buildTestNdpAdvertisement builds a minimal Neighbor Advertisement frame with a
// Target Link-Layer Address option (type 2) containing the given MAC.
func buildTestNdpAdvertisement(mac []byte) []byte {
	buf := make([]byte, 28+8)

	// ICMPv6 header (4 bytes): type=136 (NA), code=0, checksum=0
	buf[0] = 136
	buf[1] = 0
	buf[2] = 0
	buf[3] = 0

	// NA flags (4 bytes) + target address (16 bytes) — all zero for test
	// Options start at byte 24 (relative to ICMPv6 header) = byte 24 in the slice
	// Option: type=2, length=1 (units of 8 bytes), MAC (6 bytes), pad (0 bytes)
	buf[24] = 2 // option type: Target Link-Layer Address
	buf[25] = 1 // length in 8-byte units (1 * 8 = 8 bytes)
	copy(buf[26:], mac)

	return buf
}

// buildTestNdpAdvertisementWrongOptionType builds a Neighbor Advertisement with option type=1
// instead of type=2 so the MAC should not be extracted.
func buildTestNdpAdvertisementWrongOptionType(mac []byte) []byte {
	buf := buildTestNdpAdvertisement(mac)
	buf[24] = 1 // type=1: Source Link-Layer Address (not the target)
	return buf
}
