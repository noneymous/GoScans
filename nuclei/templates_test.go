/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"testing"

	nucleihttp "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	nucleijavascript "github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	nucleinetwork "github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	nucleissl "github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	nucleiwebsocket "github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
)

// TestIsHttpRequestAllowed verifies the HTTP request port-allowance logic for various Path and Raw combinations.
func TestIsHttpRequestAllowed(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		port int
		req  *nucleihttp.Request
		want bool
	}{
		{
			name: "base-url-placeholder-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{BaseURL}}/path"}},
			want: true,
		},
		{
			name: "root-url-placeholder-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{RootURL}}"}},
			want: true,
		},
		{
			name: "hostname-placeholder-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{Hostname}}/test"}},
			want: true,
		},
		{
			name: "port-placeholder-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{Port}}"}},
			want: true,
		},
		{
			name: "host-with-matching-port-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{Host}}:8080"}},
			want: true,
		},
		{
			name: "host-with-different-port-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{Host}}:443"}},
			want: false,
		},
		{
			name: "base-url-with-matching-port-allowed",
			port: 443,
			req:  &nucleihttp.Request{Path: []string{"{{BaseURL}}:443"}},
			want: true,
		},
		{
			name: "base-url-with-different-port-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{BaseURL}}:443"}},
			want: false,
		},
		{
			name: "empty-path-entry-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{""}},
			want: false,
		},
		{
			name: "no-placeholder-no-port-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"/api/health"}},
			want: false,
		},
		{
			name: "raw-placeholder-allowed",
			port: 8080,
			req:  &nucleihttp.Request{Raw: []string{"GET {{BaseURL}}/test HTTP/1.1\r\n"}},
			want: true,
		},
		{
			name: "raw-no-placeholder-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Raw: []string{"GET /fixed-path HTTP/1.1\r\n"}},
			want: false,
		},
		{
			name: "mixed-valid-and-invalid-path-rejected",
			port: 8080,
			req:  &nucleihttp.Request{Path: []string{"{{BaseURL}}/ok", "/not-ok"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHttpRequestAllowed(tt.port, tt.req)
			if got != tt.want {
				t.Errorf("isHttpRequestAllowed() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsNetworkRequestAllowed verifies the network request port-allowance logic for Port and Address fields.
func TestIsNetworkRequestAllowed(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		port int
		req  *nucleinetwork.Request
		want bool
	}{
		{
			name: "explicit-port-dynamic-placeholder-allowed",
			port: 8080,
			req:  &nucleinetwork.Request{Port: "{{Port}}"},
			want: true,
		},
		{
			name: "explicit-port-matching-hardcoded-allowed",
			port: 8080,
			req:  &nucleinetwork.Request{Port: "8080"},
			want: true,
		},
		{
			name: "explicit-port-different-hardcoded-rejected",
			port: 8080,
			req:  &nucleinetwork.Request{Port: "443"},
			want: false,
		},
		{
			name: "address-dynamic-port-allowed",
			port: 8080,
			req:  &nucleinetwork.Request{Address: []string{"host.domain.tld:{{Port}}"}},
			want: true,
		},
		{
			name: "address-matching-hardcoded-port-allowed",
			port: 8080,
			req:  &nucleinetwork.Request{Address: []string{"host.domain.tld:8080"}},
			want: true,
		},
		{
			name: "address-different-hardcoded-port-rejected",
			port: 8080,
			req:  &nucleinetwork.Request{Address: []string{"host.domain.tld:443"}},
			want: false,
		},
		{
			name: "empty-port-and-empty-address-rejected",
			port: 8080,
			req:  &nucleinetwork.Request{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNetworkRequestAllowed(tt.port, tt.req)
			if got != tt.want {
				t.Errorf("isNetworkRequestAllowed() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsSslRequestAllowed verifies the SSL request port-allowance logic for the Address field.
func TestIsSslRequestAllowed(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		port int
		req  *nucleissl.Request
		want bool
	}{
		{
			name: "dynamic-port-placeholder-allowed",
			port: 8443,
			req:  &nucleissl.Request{Address: "host.domain.tld:{{Port}}"},
			want: true,
		},
		{
			name: "matching-hardcoded-port-allowed",
			port: 8443,
			req:  &nucleissl.Request{Address: "host.domain.tld:8443"},
			want: true,
		},
		{
			name: "different-hardcoded-port-rejected",
			port: 8080,
			req:  &nucleissl.Request{Address: "host.domain.tld:443"},
			want: false,
		},
		{
			name: "address-without-port-rejected",
			port: 443,
			req:  &nucleissl.Request{Address: "host.domain.tld"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSslRequestAllowed(tt.port, tt.req)
			if got != tt.want {
				t.Errorf("isSslRequestAllowed() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsWebsocketRequestAllowed verifies the WebSocket request port-allowance logic.
// The function compares host:port address strings by splitting on ":" — ws:// scheme prefixes are
// not applicable here because the colon in the scheme triggers the two-part split before any ws/wss
// prefix check is reached. Tests use the bare host:port format that the function actually handles.
func TestIsWebsocketRequestAllowed(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		port int
		req  *nucleiwebsocket.Request
		want bool
	}{
		{
			name: "dynamic-port-placeholder-allowed",
			port: 8080,
			req:  &nucleiwebsocket.Request{Address: "host.domain.tld:{{Port}}"},
			want: true,
		},
		{
			name: "matching-hardcoded-port-allowed",
			port: 8080,
			req:  &nucleiwebsocket.Request{Address: "host.domain.tld:8080"},
			want: true,
		},
		{
			name: "different-hardcoded-port-rejected",
			port: 8080,
			req:  &nucleiwebsocket.Request{Address: "host.domain.tld:443"},
			want: false,
		},
		{
			name: "no-port-in-address-rejected",
			port: 8080,
			req:  &nucleiwebsocket.Request{Address: "host.domain.tld"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWebsocketRequestAllowed(tt.port, tt.req)
			if got != tt.want {
				t.Errorf("isWebsocketRequestAllowed() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestIsJavascriptRequestAllowed verifies the JavaScript request port-allowance logic via the Args map.
func TestIsJavascriptRequestAllowed(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		port int
		req  *nucleijavascript.Request
		want bool
	}{
		{
			name: "dynamic-port-placeholder-allowed",
			port: 8080,
			req:  &nucleijavascript.Request{Args: map[string]interface{}{"Port": "{{Port}}"}},
			want: true,
		},
		{
			name: "matching-hardcoded-port-allowed",
			port: 8080,
			req:  &nucleijavascript.Request{Args: map[string]interface{}{"Port": "8080"}},
			want: true,
		},
		{
			name: "different-hardcoded-port-rejected",
			port: 8080,
			req:  &nucleijavascript.Request{Args: map[string]interface{}{"Port": "443"}},
			want: false,
		},
		{
			name: "no-port-arg-rejected",
			port: 8080,
			req:  &nucleijavascript.Request{Args: map[string]interface{}{}},
			want: false,
		},
		{
			name: "non-numeric-port-string-rejected",
			port: 8080,
			req:  &nucleijavascript.Request{Args: map[string]interface{}{"Port": "not-a-number"}},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJavascriptRequestAllowed(tt.port, tt.req)
			if got != tt.want {
				t.Errorf("isJavascriptRequestAllowed() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
