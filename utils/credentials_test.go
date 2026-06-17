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

import "testing"

// TestValidCredentialsSet verifies that ValidOrEmptyCredentials returns false when credentials are partially set.
func TestValidCredentialsSet(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		domain   string
		user     string
		password string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid-no-creds",
			args: args{
				domain:   "",
				user:     "",
				password: "",
			},
			want: true,
		},
		{
			name: "valid-no-domain",
			args: args{
				domain:   "",
				user:     "user",
				password: "pass",
			},
			want: true,
		},
		{
			name: "valid-all",
			args: args{
				domain:   "domain",
				user:     "user",
				password: "pass",
			},
			want: true,
		},
		{
			name: "invalid-no-pass",
			args: args{
				domain:   "domain",
				user:     "user",
				password: "",
			},
			want: false,
		},
		{
			name: "invalid-no-user",
			args: args{
				domain:   "domain",
				user:     "",
				password: "pass",
			},
			want: false,
		},
		{
			name: "invalid-no-creds",
			args: args{
				domain:   "domain",
				user:     "",
				password: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidOrEmptyCredentials(tt.args.domain, tt.args.user, tt.args.password); got != tt.want {
				t.Errorf("ValidOrEmptyCredentials() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
