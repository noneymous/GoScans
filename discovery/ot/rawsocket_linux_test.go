//go:build linux

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
	"syscall"
	"testing"
	"time"
)

// TestTimeoutError_Accessors verifies that timeoutError satisfies the net.Error interface correctly.
func TestTimeoutError_Accessors(t *testing.T) {

	// Wrap a known error and verify all interface methods
	cause := syscall.EAGAIN
	e := &timeoutError{cause: cause}

	if e.Error() != cause.Error() {
		t.Errorf("timeoutError.Error() = '%v', want '%v'", e.Error(), cause.Error())
	}
	if !e.Timeout() {
		t.Error("timeoutError.Timeout() = 'false', want 'true'")
	}
	if !e.Temporary() {
		t.Error("timeoutError.Temporary() = 'false', want 'true'")
	}

	// Verify compile-time interface satisfaction (redundant but explicit)
	var _ net.Error = e
}

// TestRawConnClose_InvalidFd_ReturnsError verifies that Close propagates the syscall error.
func TestRawConnClose_InvalidFd_ReturnsError(t *testing.T) {

	// Closing an invalid fd should return an error
	conn := &rawConn{fd: -1, ifIdx: 0}
	if errClose := conn.Close(); errClose == nil {
		t.Error("rawConn.Close() expected error for invalid fd, got nil")
	}
}

// TestRawConnRead_SuccessPath verifies that rawConn.Read returns data without error when a datagram is available.
func TestRawConnRead_SuccessPath(t *testing.T) {

	// Create a pair of UDP sockets on loopback — no root required
	fdRecv, errRecv := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if errRecv != nil {
		t.Skipf("could not create recv socket: %v", errRecv)
		return
	}
	defer func() { _ = syscall.Close(fdRecv) }()

	// Bind the receive socket to an ephemeral loopback port
	bindAddr := syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}
	if errBind := syscall.Bind(fdRecv, &bindAddr); errBind != nil {
		t.Skipf("could not bind recv socket: %v", errBind)
		return
	}

	// Resolve the bound port
	sa, errName := syscall.Getsockname(fdRecv)
	if errName != nil {
		t.Skipf("could not get socket name: %v", errName)
		return
	}
	port := sa.(*syscall.SockaddrInet4).Port

	// Send a datagram from a second socket
	fdSend, errSend := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if errSend != nil {
		t.Skipf("could not create send socket: %v", errSend)
		return
	}
	defer func() { _ = syscall.Close(fdSend) }()

	payload := []byte("ping")
	dstAddr := syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	if errSnd := syscall.Sendto(fdSend, payload, 0, &dstAddr); errSnd != nil {
		t.Skipf("could not send test datagram: %v", errSnd)
		return
	}

	// Read via rawConn and confirm success
	conn := &rawConn{fd: fdRecv, ifIdx: 0}
	buf := make([]byte, 64)
	n, errRead := conn.Read(buf)
	if errRead != nil {
		t.Fatalf("rawConn.Read() error = '%v', want nil", errRead)
	}
	if n != len(payload) {
		t.Errorf("rawConn.Read() n = '%d', want '%d'", n, len(payload))
	}
}

// TestHtons verifies byte-order swapping for known values.
func TestHtons(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		in   uint16
		want uint16
	}{
		{
			name: "ethertype-ipv4",
			in:   0x0800,
			want: 0x0008,
		},
		{
			name: "ethertype-profinet",
			in:   0x8892,
			want: 0x9288,
		},
		{
			name: "zero",
			in:   0x0000,
			want: 0x0000,
		},
		{
			name: "ones",
			in:   0xFFFF,
			want: 0xFFFF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := htons(tt.in)
			if got != tt.want {
				t.Errorf("htons(%04X) = '%04X', want '%04X'", tt.in, got, tt.want)
			}
		})
	}
}

// TestRawConnWrite_ReturnsZeroOnError verifies that rawConn.Write returns (0, err) and not (len(b), err) on failure.
func TestRawConnWrite_ReturnsZeroOnError(t *testing.T) {

	// Use an invalid fd to trigger a guaranteed Sendto failure
	conn := &rawConn{fd: -1, ifIdx: 0}

	// Attempt write and verify error behavior
	n, errWrite := conn.Write([]byte{0x01, 0x02, 0x03})
	if errWrite == nil {
		t.Fatal("rawConn.Write() expected error with invalid fd, got nil")
	}
	if n != 0 {
		t.Errorf("rawConn.Write() n = '%v', want '0' on error", n)
	}
}

// TestRawConnRead_Timeout_ReturnsNetError verifies that a deadline-elapsed read returns a net.Error with Timeout() == true.
func TestRawConnRead_Timeout_ReturnsNetError(t *testing.T) {

	// Create a UDP socket — requires no special privileges and supports SO_RCVTIMEO
	fd, errSock := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if errSock != nil {
		t.Skipf("could not create socket for timeout test: %v", errSock)
		return
	}
	defer func() { _ = syscall.Close(fd) }()

	conn := &rawConn{fd: fd, ifIdx: 0}

	// Set a very short read deadline so the socket expires immediately
	errDeadline := conn.SetReadDeadline(time.Now().Add(time.Millisecond))
	if errDeadline != nil {
		t.Skipf("could not set read deadline: %v", errDeadline)
		return
	}

	// Wait briefly to ensure the deadline has elapsed
	time.Sleep(5 * time.Millisecond)

	// Attempt read — should return a timeout error
	buf := make([]byte, 16)
	_, errRead := conn.Read(buf)
	if errRead == nil {
		t.Fatal("rawConn.Read() expected timeout error, got nil")
	}

	// Verify the error is a net.Error with Timeout() == true
	netErr, ok := errRead.(net.Error)
	if !ok {
		t.Fatalf("rawConn.Read() error type = '%T', want net.Error", errRead)
	}
	if !netErr.Timeout() {
		t.Errorf("rawConn.Read() Timeout() = '%v', want 'true'", netErr.Timeout())
	}
}
