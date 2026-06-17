/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"testing"
)

// TestResolvesToIp verifies that ResolvesToIp correctly reports whether a hostname resolves to the expected IP address.
func TestResolvesToIp(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		hostname   string
		expectedIp string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid-resolving",
			args: args{hostname: "www.ccc.de", expectedIp: "195.54.164.39"},
			want: true,
		},
		{
			name: "invalid-confused-input",
			args: args{hostname: "195.54.164.39", expectedIp: "www.ccc.de"},
			want: false, // Ip as hostname can be resolved to itself :)
		},
		{
			name: "invalid-resolving",
			args: args{hostname: "sub.domain.tld", expectedIp: "195.54.164.39"},
			want: false,
		},
		{
			name: "invalid-not-resolving",
			args: args{hostname: "notexisting.domain.tld", expectedIp: "195.54.164.39"},
			want: false,
		},
		{
			name: "invalid-hostname",
			args: args{hostname: "", expectedIp: "195.54.164.39"},
			want: false,
		},
		{
			name: "invalid-ip1",
			args: args{hostname: "google.com", expectedIp: "notanipaddress"},
			want: false,
		},
		{
			name: "invalid-ip2",
			args: args{hostname: "google.com", expectedIp: ""},
			want: false,
		},
		{
			name: "invalid-input",
			args: args{hostname: "", expectedIp: ""},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvesToIp(tt.args.hostname, tt.args.expectedIp); got != tt.want {
				t.Errorf("ResolvesToIp() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestResolvesToHostname verifies that ResolvesToHostname correctly reports whether an IP address resolves to the expected hostname.
func TestResolvesToHostname(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		ip               string
		expectedHostname string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid-resolving",
			args: args{ip: "8.8.4.4", expectedHostname: "dns.google"},
			want: true,
		},
		{
			name: "invalid",
			args: args{ip: "8.8.4.4", expectedHostname: "notexisting"},
			want: false,
		},
		{
			name: "invalid-ip",
			args: args{ip: "a.12.12.a", expectedHostname: "google.com"},
			want: false,
		},
		{
			name: "invalid-empty-ip",
			args: args{ip: "", expectedHostname: "google.com"},
			want: false,
		},
		{
			name: "invalid-empty-hostname",
			args: args{ip: "192.168.0.1", expectedHostname: ""},
			want: false,
		},
		{
			name: "invalid-not-resolving",
			args: args{ip: "192.168.0.1", expectedHostname: "scan.domain.tld"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvesToHostname(tt.args.ip, tt.args.expectedHostname); got != tt.want {
				t.Errorf("ResolvesToHostname() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidHostname verifies that IsValidHostname correctly identifies valid and invalid hostnames.
func TestIsValidHostname(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{
			name:     "valid",
			hostname: "hostname",
			want:     true, // hostname without domain can be valid too in local environments, systems are automatically resolving to the local domain
		},
		{
			name:     "valid2",
			hostname: "tfpr-a0-p03",
			want:     true, // hostname without domain can be valid too in local environments, systems are automatically resolving to the local domain
		},
		{
			name:     "valid3",
			hostname: "sub.domain.tld",
			want:     true,
		},
		{
			name:     "valid-hyphen",
			hostname: "s-ub.domain.tld",
			want:     true,
		},
		{
			name:     "valid-localhost",
			hostname: "localhost",
			want:     true,
		},
		{
			name:     "valid-hostname",
			hostname: "hostname",
			want:     true, // within an AD domain it's also possible to contact hostnames, instead of fqdns
		},
		{
			name:     "invalid-hyphen",
			hostname: "-sub.domain.tld",
			want:     false,
		},
		{
			name:     "invalid1",
			hostname: "!=§$%",
			want:     false,
		},
		{
			name:     "invalid2",
			hostname: "sub.domain.tld/26",
			want:     false,
		},
		{
			name:     "invalid4",
			hostname: "sub.domain.tld\\26",
			want:     false,
		},
		{
			name:     "invalid-dn",
			hostname: "cn=0123456ab,cn=forrest,cn=domain,cn=tld",
			want:     false,
		},
		{
			name:     "invalid-empty",
			hostname: "",
			want:     false,
		},
		{
			name:     "invalid-empty-space",
			hostname: " ",
			want:     false,
		},
		{
			name:     "invalid-space",
			hostname: "su b.domain.tld",
			want:     false,
		},
		{
			name:     "invalid-space2",
			hostname: "t ld",
			want:     false,
		},
		{
			name:     "invalid-start",
			hostname: ".tld",
			want:     false,
		},
		{
			name:     "invalid-start2",
			hostname: " tld",
			want:     false,
		},
		{
			name:     "invalid-start3",
			hostname: "-tld",
			want:     false,
		},
		{
			name:     "invalid-end",
			hostname: "tld.",
			want:     false,
		},
		{
			name:     "invalid-end2",
			hostname: "tld ",
			want:     false,
		},
		{
			name:     "invalid-end3",
			hostname: "tld-",
			want:     false,
		},
		{
			name:     "invalid-ipv4",
			hostname: "127.0.0.1",
			want:     false,
		},
		{
			name:     "invalid-ipv4-2",
			hostname: "8.8.8.8",
			want:     false,
		},
		{
			name:     "invalid-ipv6",
			hostname: "1::",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidHostname(tt.hostname); got != tt.want {
				t.Errorf("IsValidHostname() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidIp verifies that IsValidIp correctly identifies valid IPv4 and IPv6 addresses while rejecting ranges, hostnames, and ports.
func TestIsValidIp(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "ipv4-localhost",
			s:    "127.0.0.1",
			want: true,
		},
		{
			name: "ipv4-1",
			s:    "8.8.8.8",
			want: true,
		},
		{
			name: "ipv4-2",
			s:    "123.123.123.123",
			want: true,
		},

		{
			name: "ipv6-localhost",
			s:    "1::",
			want: true,
		},
		{
			name: "ipv6",
			s:    "fe80:3::1ff:fe23:4567:890a",
			want: true,
		},
		{
			name: "ipv6-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]",
			want: false,
		},

		{
			name: "ipv4-range-1",
			s:    "192.168.0.1/32",
			want: false,
		},
		{
			name: "ipv4-range-254",
			s:    "192.168.0.1/24",
			want: false,
		},
		{
			name: "ipv4-range-4294967294",
			s:    "192.168.0.1/0",
			want: false,
		},
		{
			name: "ipv4-range-2147483646",
			s:    "192.168.0.1/1",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016",
			s:    "1::/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-2",
			s:    "fe80:3::1ff:fe23:4567:890a/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]/24",
			want: false,
		},

		{
			name: "domain-tld",
			s:    "domain.tld",
			want: false,
		},
		{
			name: "domain-root",
			s:    "domain",
			want: false,
		},

		{
			name: "ipv4-with-port",
			s:    "123.123.123.123:443",
			want: false,
		},
		{
			name: "ipv6-with-port",
			s:    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
			want: false,
		},
		{
			name: "domain-with-port",
			s:    "domain.tld:443",
			want: false,
		},

		{
			name: "grabage",
			s:    "in valid",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIp(tt.s); got != tt.want {
				t.Errorf("IsValidIp() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidIpV4 verifies that IsValidIpV4 accepts valid IPv4 addresses and rejects IPv6, ranges, hostnames, and addresses with ports.
func TestIsValidIpV4(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "ipv4-localhost",
			s:    "127.0.0.1",
			want: true,
		},
		{
			name: "ipv4-1",
			s:    "8.8.8.8",
			want: true,
		},
		{
			name: "ipv4-2",
			s:    "123.123.123.123",
			want: true,
		},

		{
			name: "ipv6-localhost",
			s:    "1::",
			want: false,
		},
		{
			name: "ipv6",
			s:    "fe80:3::1ff:fe23:4567:890a",
			want: false,
		},
		{
			name: "ipv6-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]",
			want: false,
		},

		{
			name: "ipv4-range-1",
			s:    "192.168.0.1/32",
			want: false,
		},
		{
			name: "ipv4-range-254",
			s:    "192.168.0.1/24",
			want: false,
		},
		{
			name: "ipv4-range-4294967294",
			s:    "192.168.0.1/0",
			want: false,
		},
		{
			name: "ipv4-range-2147483646",
			s:    "192.168.0.1/1",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016",
			s:    "1::/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-2",
			s:    "fe80:3::1ff:fe23:4567:890a/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]/24",
			want: false,
		},

		{
			name: "domain-tld",
			s:    "domain.tld",
			want: false,
		},
		{
			name: "domain-root",
			s:    "domain",
			want: false,
		},

		{
			name: "ipv4-with-port",
			s:    "123.123.123.123:443",
			want: false,
		},
		{
			name: "ipv6-with-port",
			s:    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
			want: false,
		},
		{
			name: "domain-with-port",
			s:    "domain.tld:443",
			want: false,
		},

		{
			name: "grabage",
			s:    "in valid",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpV4(tt.s); got != tt.want {
				t.Errorf("IsValidIpV4() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidIpV6 verifies that IsValidIpV6 accepts valid IPv6 addresses and rejects IPv4, ranges, hostnames, and addresses with ports.
func TestIsValidIpV6(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "ipv4-localhost",
			s:    "127.0.0.1",
			want: false,
		},
		{
			name: "ipv4-1",
			s:    "8.8.8.8",
			want: false,
		},
		{
			name: "ipv4-2",
			s:    "123.123.123.123",
			want: false,
		},

		{
			name: "ipv6-localhost",
			s:    "1::",
			want: true,
		},
		{
			name: "ipv6",
			s:    "fe80:3::1ff:fe23:4567:890a",
			want: true,
		},
		{
			name: "ipv6-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]",
			want: false,
		},

		{
			name: "ipv4-range-1",
			s:    "192.168.0.1/32",
			want: false,
		},
		{
			name: "ipv4-range-254",
			s:    "192.168.0.1/24",
			want: false,
		},
		{
			name: "ipv4-range-4294967294",
			s:    "192.168.0.1/0",
			want: false,
		},
		{
			name: "ipv4-range-2147483646",
			s:    "192.168.0.1/1",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016",
			s:    "1::/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-2",
			s:    "fe80:3::1ff:fe23:4567:890a/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]/24",
			want: false,
		},

		{
			name: "domain-tld",
			s:    "domain.tld",
			want: false,
		},
		{
			name: "domain-root",
			s:    "domain",
			want: false,
		},

		{
			name: "ipv4-with-port",
			s:    "123.123.123.123:443",
			want: false,
		},
		{
			name: "ipv6-with-port",
			s:    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
			want: false,
		},
		{
			name: "domain-with-port",
			s:    "domain.tld:443",
			want: false,
		},

		{
			name: "grabage",
			s:    "in valid",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpV6(tt.s); got != tt.want {
				t.Errorf("IsValidIpV6() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidIpRange verifies that IsValidIpRange accepts valid CIDR ranges and rejects bare IPs, hostnames, and addresses with ports.
func TestIsValidIpRange(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "ipv4-localhost",
			s:    "127.0.0.1",
			want: false,
		},
		{
			name: "ipv4-1",
			s:    "8.8.8.8",
			want: false,
		},
		{
			name: "ipv4-2",
			s:    "123.123.123.123",
			want: false,
		},

		{
			name: "ipv6-localhost",
			s:    "1::",
			want: false,
		},
		{
			name: "ipv6",
			s:    "fe80:3::1ff:fe23:4567:890a",
			want: false,
		},
		{
			name: "ipv6-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]",
			want: false,
		},

		{
			name: "ipv4-range-1",
			s:    "192.168.0.1/32",
			want: true,
		},
		{
			name: "ipv4-range-254",
			s:    "192.168.0.1/24",
			want: true,
		},
		{
			name: "ipv4-range-4294967294",
			s:    "192.168.0.1/0",
			want: true,
		},
		{
			name: "ipv4-range-2147483646",
			s:    "192.168.0.1/1",
			want: true,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016",
			s:    "1::/24",
			want: true,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-2",
			s:    "fe80:3::1ff:fe23:4567:890a/24",
			want: true,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]/24",
			want: false,
		},

		{
			name: "domain-tld",
			s:    "domain.tld",
			want: false,
		},
		{
			name: "domain-root",
			s:    "domain",
			want: false,
		},

		{
			name: "ipv4-with-port",
			s:    "123.123.123.123:443",
			want: false,
		},
		{
			name: "ipv6-with-port",
			s:    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
			want: false,
		},
		{
			name: "domain-with-port",
			s:    "domain.tld:443",
			want: false,
		},

		{
			name: "grabage",
			s:    "in valid",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpRange(tt.s); got != tt.want {
				t.Errorf("IsValidIpRange() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsValidTarget verifies that IsValidAddress accepts valid IPs and hostnames while rejecting ranges, ports, and malformed input.
func TestIsValidTarget(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{
			name: "ipv4-localhost",
			s:    "127.0.0.1",
			want: true,
		},
		{
			name: "ipv4-1",
			s:    "8.8.8.8",
			want: true,
		},
		{
			name: "ipv4-2",
			s:    "123.123.123.123",
			want: true,
		},

		{
			name: "ipv6-localhost",
			s:    "1::",
			want: true,
		},
		{
			name: "ipv6",
			s:    "fe80:3::1ff:fe23:4567:890a",
			want: true,
		},
		{
			name: "ipv6-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]",
			want: false,
		},

		{
			name: "ipv4-range-1",
			s:    "192.168.0.1/32",
			want: false,
		},
		{
			name: "ipv4-range-254",
			s:    "192.168.0.1/24",
			want: false,
		},
		{
			name: "ipv4-range-4294967294",
			s:    "192.168.0.1/0",
			want: false,
		},
		{
			name: "ipv4-range-2147483646",
			s:    "192.168.0.1/1",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016",
			s:    "1::/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-2",
			s:    "fe80:3::1ff:fe23:4567:890a/24",
			want: false,
		},
		{
			name: "ipv6-range-20282409603651670423947251286016-embraced",
			s:    "[fe80:3::1ff:fe23:4567:890a]/24",
			want: false,
		},

		{
			name: "domain-tld",
			s:    "domain.tld",
			want: true,
		},
		{
			name: "domain-root",
			s:    "domain",
			want: true,
		},

		{
			name: "ipv4-with-port",
			s:    "123.123.123.123:443",
			want: false,
		},
		{
			name: "ipv6-with-port",
			s:    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
			want: false,
		},
		{
			name: "domain-with-port",
			s:    "domain.tld:443",
			want: false,
		},

		{
			name: "grabage",
			s:    "in valid",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAddress(tt.s); got != tt.want {
				t.Errorf("IsValidAddress() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
