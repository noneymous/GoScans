/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"crypto/x509"
	"testing"

	"github.com/siemens/GoScans/utils"
)

// Test_makeKeyUsage verifies that makeKeyUsageSlice converts X.509 key usage bitmasks to human-readable string slices.
func Test_makeKeyUsage(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		logger utils.Logger
		input  x509.KeyUsage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// The invalid tests will produce some warnings
		{
			name: "zero",
			args: args{logger: testLogger, input: 0},
			want: []string{},
		},
		{
			name: "invalid-1",
			args: args{logger: testLogger, input: -1},
			want: []string{},
		},
		{
			name: "invalid-2",
			args: args{logger: testLogger, input: 513},
			want: []string{},
		},
		{
			name: "invalid-3",
			args: args{logger: testLogger, input: 512},
			want: []string{},
		},
		{
			name: "valid-1",
			args: args{logger: testLogger, input: 81},
			want: []string{"Digital Signature", "Key Agreement", "CRL Sign"},
		},
		{
			name: "valid-2",
			args: args{logger: testLogger, input: 436},
			want: []string{"Key Encipherment", "Key Agreement", "Cert Sign", "Encipher Only", "Decipher Only"},
		},
		{
			name: "valid-3",
			args: args{logger: testLogger, input: 511},
			want: []string{"Digital Signature", "Content Commitment", "Key Encipherment", "Data Encipherment", "Key Agreement", "Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := makeKeyUsageSlice(tt.args.logger, tt.args.input)
			if !utils.Equals(res, tt.want) {
				t.Errorf("makeKeyUsageSlice() got = '%v', want = '%v'", res, tt.want)
			}
		})
	}
}

// Test_makeExtKeyUsage verifies that makeExtKeyUsageSlice converts X.509 extended key usage values to human-readable string slices.
func Test_makeExtKeyUsage(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		logger utils.Logger
		input  []x509.ExtKeyUsage
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		// The invalid tests will produce some warnings
		{
			name: "empty",
			args: args{logger: testLogger, input: []x509.ExtKeyUsage{}},
			want: []string{},
		},
		{
			name: "invalid-lower-bound",
			args: args{logger: testLogger, input: []x509.ExtKeyUsage{-1}},
			want: []string{},
		},
		{
			name: "invalid-upper-bound",
			args: args{logger: testLogger, input: []x509.ExtKeyUsage{14}},
			want: []string{},
		},
		{
			name: "invalid-mixed",
			args: args{logger: testLogger, input: []x509.ExtKeyUsage{-1, 3}},
			want: []string{},
		},
		{
			name: "valid-all",
			args: args{
				logger: testLogger,
				input:  []x509.ExtKeyUsage{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
			},
			want: []string{"Any", "Server Auth", "Client Auth", "Code Signing", "Email Protection", "IP SEC End System", "IP SEC Tunnel", "IP SEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing"},
		},
		{
			name: "valid-order",
			args: args{
				logger: testLogger,
				input:  []x509.ExtKeyUsage{2, 12, 6, 9, 13, 10, 3, 7, 0, 1, 4, 8, 5, 11},
			},
			want: []string{"Any", "Server Auth", "Client Auth", "Code Signing", "Email Protection", "IP SEC End System", "IP SEC Tunnel", "IP SEC User", "Time Stamping", "OCSP Signing", "Microsoft Server Gated Crypto", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing", "Microsoft Kernel Code Signing"},
		},
		{
			name: "valid-some-and-order",
			args: args{
				logger: testLogger,
				input:  []x509.ExtKeyUsage{2, 12, 6, 9, 3, 7, 0, 11},
			},
			want: []string{"Any", "Client Auth", "Code Signing", "IP SEC Tunnel", "IP SEC User", "OCSP Signing", "Netscape Server Gated Crypto", "Microsoft Commercial Code Signing"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := makeExtKeyUsageSlice(tt.args.logger, tt.args.input)
			if !utils.Equals(res, tt.want) {
				t.Errorf("makeExtKeyUsageSlice() got = '%v', want = '%v'", res, tt.want)
			}
		})
	}
}
