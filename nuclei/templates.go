package nuclei

import (
	"fmt"
	"strconv"
	"strings"

	nucleihttp "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	nucleijavascript "github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	nucleinetwork "github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	nucleissl "github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	nucleiwebsocket "github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	nucleitemplates "github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/siemens/GoScans/utils"
)

// GetPortTemplates returns the IDs of templates relevant for a given port.
// Inclusion logic:
//   - If includeIds is empty:
//     Include templates that match the provided port OR have a dynamic port
//     AND whose ID is not in excludeIds
//   - If includeIds is not empty:
//     Include templates whose ID is in includeIds AND
//     have a port matching the provided port OR a dynamic port
func GetPortTemplates(
	logger utils.Logger,
	pathTemplates string,
	port int,
	includeIds []string,
	excludeIds []string,
) ([]string, error) {

	// Prepare list of actually included template IDs.
	// This list starts empty and is filled with templates surviving the validation logic below.
	var templateIds []string

	// Create quick lookup map for excludeIds
	lookupDisallowed := make(map[string]struct{}, len(excludeIds))
	for _, id := range excludeIds {
		lookupDisallowed[id] = struct{}{}
	}

	// Create quick lookup map for includeIds
	lookupAllowed := make(map[string]struct{}, len(includeIds))
	for _, id := range includeIds {
		lookupAllowed[id] = struct{}{}
	}

	// Prepare action to take on each loaded template
	fnWalkCallback := func(tplPath string, tpl *nucleitemplates.Template) error {

		// Skip template if it is on the exclude list
		if _, disallowed := lookupDisallowed[tpl.ID]; disallowed {
			return nil
		}

		// Skip template, if it is outside the include list
		if len(lookupAllowed) > 0 {
			if _, allowed := lookupAllowed[tpl.ID]; !allowed {
				return nil
			}
		}

		// Skip template if it is purely host-based (DNS / WHOIS) for a service scan
		if len(tpl.RequestsDNS) > 0 || len(tpl.RequestsWHOIS) > 0 {
			return nil
		}

		// Skip template, if it contains HTTP requests not allowed
		for _, r := range tpl.RequestsHTTP {
			if !isHttpRequestAllowed(port, r) {
				return nil
			}
		}

		// Skip template, if it contains Javascript requests not allowed
		for _, r := range tpl.RequestsJavascript {
			if !isJavascriptRequestAllowed(port, r) {
				return nil
			}
		}

		// Skip template, if it contains network requests not allowed
		for _, r := range tpl.RequestsNetwork {
			if !isNetworkRequestAllowed(port, r) {
				return nil
			}
		}

		// Skip template, if it contains SSL requests not allowed
		for _, r := range tpl.RequestsSSL {
			if !isSslRequestAllowed(port, r) {
				return nil
			}
		}

		// Skip template, if it contains WebSocket not allowed
		for _, r := range tpl.RequestsWebsocket {
			if !isWebsocketRequestAllowed(port, r) {
				return nil
			}
		}

		// Skip template, if it contains no port-sensitive requests at all
		if len(tpl.RequestsHTTP) == 0 &&
			len(tpl.RequestsNetwork) == 0 &&
			len(tpl.RequestsSSL) == 0 &&
			len(tpl.RequestsWebsocket) == 0 &&
			len(tpl.RequestsJavascript) == 0 {
			return nil
		}

		// Append to actual list of included templates
		templateIds = append(templateIds, tpl.ID)

		// Return nil to keep walking
		return nil
	}

	// Walk templates
	errWalk := walkTemplates(logger, pathTemplates, fnWalkCallback)
	if errWalk != nil {
		return nil, errWalk
	}

	// Return templates
	return templateIds, nil
}

// --------------------------
// Per-protocol checks
// --------------------------

// isHttpRequestAllowed checks whether an HTTP request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/http#Request
// The rules are:
// - Accept entries that contain dynamic placeholders implying port injection ({{Port}}, {{BaseURL}}, etc.)
// - Accept entries that explicitly hardcode the requested port in a Host:Port pattern
func isHttpRequestAllowed(port int, req *nucleihttp.Request) bool {

	// User port string for comparisons
	userPortStr := strconv.Itoa(port)

	// Helper that validates a single string entry (Path or Raw)
	checkEntry := func(s string) bool {

		// Empty entries are invalid
		if s == "" {
			return false
		}

		// Case: {{Host}}:<port>
		if strings.Contains(s, "{{Host}}:") || strings.Contains(s, "{{Hostname}}:") || strings.Contains(s, "{{BaseURL}}:") {

			m := portRegex.FindStringSubmatch(s)
			if m != nil {
				// Explicit port found → must match exactly
				return m[1] == userPortStr
			}

			// Not matching ports -> reject
			return false
		}

		// Accept known service-oriented placeholders that imply port injection
		if strings.Contains(s, "{{BaseURL}}") ||
			strings.Contains(s, "{{RootURL}}") ||
			strings.Contains(s, "{{Hostname}}") ||
			strings.Contains(s, "{{Port}}") {
			return true
		}

		// Default reject
		return false
	}

	// Validate all Path entries; if any fails, the request is not allowed
	for _, p := range req.Path {
		if !checkEntry(p) {
			return false
		}
	}

	// Validate all Raw entries; if any fails, the request is not allowed
	for _, r := range req.Raw {
		if !checkEntry(r) {
			return false
		}
	}

	// All entries passed → HTTP request allowed
	return true
}

// isNetworkRequestAllowed checks whether a network request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/network#Request
// Rules:
// - If explicit Port field is present, it must be "{{Port}}" or equal to the UserPort.
// - Otherwise, check Address entries for either ":{{Port}}" or a hardcoded host:port matching UserPort.
func isNetworkRequestAllowed(port int, req *nucleinetwork.Request) bool {

	// User port string for comparisons
	userPortStr := strconv.Itoa(port)

	// Case 1: Explicit Port field
	if req.Port != "" {
		// Accept dynamic placeholder
		if req.Port == "{{Port}}" {
			return true
		}
		// Accept exact hardcoded port equal to the user port
		if req.Port == userPortStr {
			return true
		}
		return false
	}

	// Case 2: Check each Address in the slice
	for _, addr := range req.Address {
		// Dynamic port injection pattern -> allow.
		if strings.Contains(addr, ":{{Port}}") {
			return true
		}

		// Hardcoded host:port pattern -> compare it with user port
		m := portRegex.FindStringSubmatch(addr)
		if m != nil && m[1] == userPortStr {
			return true
		}
	}

	// Default reject
	return false
}

// isSslRequestAllowed checks whether an SSL request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/ssl#Request
// Acceptance rules:
// - Accept dynamic ":{{Port}}" patterns.
// - Accept explicit host:port with the exact user port.
func isSslRequestAllowed(port int, req *nucleissl.Request) bool {

	// If address contains the dynamic placeholder for Port, allow it.
	if strings.Contains(req.Address, ":{{Port}}") {
		return true
	}

	// If address is in host:port format, check if port matches the user port.
	m := portRegex.FindStringSubmatch(req.Address)
	if m != nil {
		// Explicit port found → must match exactly
		return m[1] == strconv.Itoa(port)
	}

	// Default reject
	return false
}

// isWebsocketRequestAllowed checks whether a WebSocket request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/websocket#Request
// Acceptance rules:
// - Accept ":{{Port}}" dynamic injection.
// - Accept hardcoded host:port equal to UserPort.
// - If no explicit port is present use standard ws/wss defaults (80/443).
func isWebsocketRequestAllowed(port int, req *nucleiwebsocket.Request) bool {

	// Extract the address to evaluate
	addr := req.Address

	// Allow dynamic port injection patterns
	if strings.Contains(addr, ":{{Port}}") {
		return true
	}

	m := portRegex.FindStringSubmatch(addr)
	if m != nil {
		// Explicit port found → must match exactly
		return m[1] == strconv.Itoa(port)
	}

	// No explicit port: allow standard ws/wss defaults when they match user port
	if strings.HasPrefix(addr, "ws://") && port == 80 {
		return true
	}
	if strings.HasPrefix(addr, "wss://") && port == 443 {
		return true
	}

	// Default reject
	return false
}

// isJavascriptRequestAllowed checks whether a JavaScript request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/javascript#Request
// Accepts when the "Port" arg exists and either uses "{{Port}}" or hardcodes the matching user port.
func isJavascriptRequestAllowed(port int, req *nucleijavascript.Request) bool {

	// Look up the "Port" argument in the request's Args map
	portVal, ok := req.Args["Port"]
	if !ok {
		// No port argument provided → reject
		return false
	}

	// Convert the value to string
	portStr := fmt.Sprint(portVal)

	// Allow the dynamic placeholder
	if portStr == "{{Port}}" {
		return true
	}

	// If the port argument is numeric, compare to the UserPort
	p, errP := strconv.Atoi(portStr)
	if errP == nil {
		return p == port
	}

	// Default reject
	return false
}
