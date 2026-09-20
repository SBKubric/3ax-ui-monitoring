package probe

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"testing"
)

// The tests need a socks5 proxy on loopback because that is the only thing
// the xray probe knows about a tunnel: Transport.Proxy =
// socks5://127.0.0.1:<port> (spec §5). A ~60-line no-auth CONNECT server
// stands in for the xray child's socks inbound, so the probe is exercised end
// to end — greeting, CONNECT, TLS through the tunnel to the mon-server stub —
// without a real xray binary (testing policy: fake the boundary, no network
// beyond loopback).

// startSOCKS runs a no-auth socks5 CONNECT proxy on a loopback port until the
// test ends. When forward is false it completes the CONNECT and then never
// moves a byte, which is how a tunnel that is up but dead looks from the
// probe's side: the TLS handshake hangs (spec §5, tls_timeout).
func startSOCKS(t *testing.T, forward bool) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(conn, forward)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// serveSOCKS speaks just enough of RFC 1928 for net/http's socks dialer: the
// no-auth greeting, one CONNECT request, and a success reply.
func serveSOCKS(conn net.Conn, forward bool) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	head := make([]byte, 2) // VER, NMETHODS
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, int(head[1]))); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no authentication
		return
	}

	req := make([]byte, 4) // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	host, ok := readAddr(br, req[3])
	if !ok {
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	// Success, bound address 0.0.0.0:0 — net/http ignores it.
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if !forward {
		_, _ = io.Copy(io.Discard, br) // swallow the ClientHello, answer nothing
		return
	}

	up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(conn, up)
}

// readAddr reads the CONNECT target address of the given ATYP.
func readAddr(br *bufio.Reader, atyp byte) (string, bool) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		return net.IP(b).String(), true
	case 0x03: // domain name
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", false
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		return string(b), true
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", false
		}
		return net.IP(b).String(), true
	}
	return "", false
}

// closedPort returns a loopback port with nothing listening on it — the
// tcp_refused case (xray down, or an inbound that never came up).
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}
