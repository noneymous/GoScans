//go:build windows

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
	"time"
)

// rawConn is a stub on Windows - L2 raw sockets require Npcap/WinPcap which is not implemented yet
type rawConn struct{}

// openRawEthernetSocket is not supported on Windows
func openRawEthernetSocket(ifi *net.Interface, etherType uint16) (*rawConn, error) {
	return nil, fmt.Errorf("raw Ethernet sockets for OT L2 discovery are not supported on Windows")
}

// Write is not supported on Windows
func (c *rawConn) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("not supported on Windows")
}

// Read is not supported on Windows
func (c *rawConn) Read(b []byte) (int, error) {
	return 0, fmt.Errorf("not supported on Windows")
}

// SetReadDeadline is not supported on Windows
func (c *rawConn) SetReadDeadline(t time.Time) error {
	return nil
}

// Close is not supported on Windows
func (c *rawConn) Close() error {
	return nil
}
