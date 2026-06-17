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

// TestHashSha1 verifies that HashSha1 returns the correct SHA1 hex string with and without a separator.
func TestHashSha1(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		arr []byte
		sep string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "no-sep",
			args: args{arr: []byte("test"), sep: ""},
			want: "A94A8FE5CCB19BA61C4C0873D391E987982FBBD3",
		},
		{
			name: "with-sep",
			args: args{arr: []byte("test"), sep: ":"},
			want: "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashSha1(tt.args.arr, tt.args.sep); got != tt.want {
				t.Errorf("HashSha1() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
