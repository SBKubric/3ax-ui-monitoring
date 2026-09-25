package awg

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// probeBind is the conn.Bind every probe device sends and receives on: one
// dual-stack UDP socket, read and written one datagram at a time (#90).
//
// It replaces conn.NewDefaultBind() for the sake of BatchSize alone. On
// linux the default bind batches 128 datagrams per syscall, and
// amneziawg-go sizes its buffers by that: 128 × 64 KiB for each of the
// two receive routines (v4, v6) and for the TUN reader, ~25 MB per device.
// A probe device lives for one handshake and a few HTTPS packets, and
// mon-client builds one per AWG target a minute; after Close those buffers
// sit in the device's sync.Pool through two GCs, so the heap target, and
// with it RSS, stayed several times the live heap — enough to push a small
// stand box into swap and stall whole cycles for seconds (#85). With batch
// 1 a device takes one buffer per routine.
//
// Wrapping the default bind and only overriding BatchSize is not an option:
// with UDP receive offload (GRO) on linux it reads coalesced datagrams into
// the tail of its own 128-message array and splits them back to the head,
// so it assumes the caller handed it a full batch of buffers — with one,
// the read would land in messages that have none.
//
// What the default bind has beyond that, a probe does not need:
//   - no SO_MARK: a mark only steers a kernel interface's traffic through
//     policy routing, and mon-client runs without the CAP_NET_ADMIN setting
//     one takes (spec §1); SetMark is a no-op;
//   - no sticky source address: a probe device lives for seconds and the
//     kernel's route choice is the right one for every packet of it;
//   - no separate IPv4 and IPv6 sockets: one "udp" socket on the
//     unspecified address is dual-stack wherever the host has IPv6, and a
//     plain IPv4 socket where it has not.
//
// A probeBind is safe for concurrent use, as amneziawg-go requires.
type probeBind struct {
	mu   sync.Mutex
	conn *net.UDPConn // nil while closed
}

var _ conn.Bind = (*probeBind)(nil)

func newProbeBind() *probeBind { return &probeBind{} }

// Open listens on port, 0 meaning any, and returns the one receive function
// that reads the socket. amneziawg-go calls it from BindUpdate after Close,
// so a bind is reopened every time its device comes up.
func (b *probeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, fmt.Errorf("probe bind: listen on udp port %d: %w", port, err)
	}
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{receiveFrom(c)}, actual, nil
}

// receiveFrom reads one datagram per call into packets[0]. It is bound to
// c rather than to the bind, so a receive routine of a closed-and-reopened
// bind can only ever see its own socket's net.ErrClosed — which is what
// ends amneziawg-go's RoutineReceiveIncoming.
func receiveFrom(c *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, from, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = newProbeEndpoint(from)
		return 1, nil
	}
}

// Close closes the socket. It is safe to call on a bind that is already
// closed or was never opened: amneziawg-go closes the bind both before
// every Open and when the device goes away.
func (b *probeBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

// SetMark does nothing; see probeBind for why a probe has no mark.
func (*probeBind) SetMark(uint32) error { return nil }

// Send writes each buffer as its own datagram. bufs may hold more than
// BatchSize buffers: amneziawg-go sends an initiation together with its
// Jc junk packets in one call.
func (b *probeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	to, ok := ep.(*probeEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, to.dst); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint reads a UAPI `endpoint=` value, which is always ip:port:
// the probe has already resolved a host name (spec §5).
func (*probeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("probe bind: endpoint %q: %w", s, err)
	}
	return newProbeEndpoint(ap), nil
}

// BatchSize is the whole point of probeBind; see there.
func (*probeBind) BatchSize() int { return 1 }

// probeEndpoint is a peer address and nothing else: probeBind never pins a
// source address, so every Src method is empty.
type probeEndpoint struct {
	dst netip.AddrPort
}

var _ conn.Endpoint = (*probeEndpoint)(nil)

// newProbeEndpoint unmaps a v4-mapped address: a dual-stack socket reports
// IPv4 senders as ::ffff:a.b.c.d, and the peer must read the same however
// it reached us — in the UAPI dump, and in the mac2 cookie, which hashes
// DstToBytes.
func newProbeEndpoint(ap netip.AddrPort) *probeEndpoint {
	return &probeEndpoint{dst: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
}

func (*probeEndpoint) ClearSrc()             {}
func (*probeEndpoint) SrcToString() string   { return "" }
func (*probeEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e *probeEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *probeEndpoint) DstToString() string { return e.dst.String() }

func (e *probeEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}
