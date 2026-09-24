package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// nicID is the one NIC every netTUN's stack has.
const nicID tcpip.NICID = 1

// netTUN is the gVisor netstack behind a Device: the tun.Device
// amneziawg-go reads outbound packets from and writes decrypted inbound
// ones into, plus the TCP dialer the probe rides.
//
// It replaces amneziawg-go's own tun/netstack (CreateNetTUN) because that
// one cannot be closed safely (#69): its Close closes the channel
// WriteNotify sends outbound packets on, while gVisor's TCP goroutines may
// still be calling WriteNotify — a late segment for a just-closed
// connection is answered with an RST from a gVisor processor goroutine
// after the probe has already closed everything it owns. That is a data
// race at best and a "send on closed channel" panic of the whole
// mon-client at worst, and nothing a caller does before Close can prevent
// it, because the sender is the stack itself.
//
// This copy keeps upstream's stack setup and packet plumbing and differs
// only in how it shuts down: the packet channel is never closed. Close
// closes done instead, every blocking send and receive selects on it, and
// the stack is waited out (stack.Wait) so no gVisor goroutine outlives the
// device. It also carries only what a probe needs — TCP, no UDP, ICMP or
// DNS: mon-client dials mon-server by address (spec §4).
type netTUN struct {
	ep           *channel.Endpoint
	stack        *stack.Stack
	notifyHandle *channel.NotificationHandle
	events       chan tun.Event
	incoming     chan *buffer.View
	mtu          int

	done      chan struct{}
	closeOnce sync.Once
}

var _ tun.Device = (*netTUN)(nil)

// newNetTUN builds a stack with one NIC holding localAddresses and a
// default route per address family, the way amneziawg-go's CreateNetTUN
// does.
func newNetTUN(localAddresses []netip.Addr, mtu int) (*netTUN, error) {
	t := &netTUN{
		ep: channel.New(1024, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			HandleLocal:        true,
		}),
		events:   make(chan tun.Event, 1),
		incoming: make(chan *buffer.View),
		mtu:      mtu,
		done:     make(chan struct{}),
	}
	fail := func(format string, args ...any) (*netTUN, error) {
		t.stack.Destroy()
		return nil, fmt.Errorf(format, args...)
	}
	sack := tcpip.TCPSACKEnabled(true) // gVisor has TCP SACK off by default
	if err := t.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail("enable TCP SACK: %v", err)
	}
	t.notifyHandle = t.ep.AddNotify(t)
	if err := t.stack.CreateNIC(nicID, t.ep); err != nil {
		return fail("create NIC: %v", err)
	}
	var hasV4, hasV6 bool
	for _, ip := range localAddresses {
		proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
		if ip.Is6() {
			proto = ipv6.ProtocolNumber
		}
		addr := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if err := t.stack.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
			return fail("add address %v: %v", ip, err)
		}
		hasV4 = hasV4 || ip.Is4()
		hasV6 = hasV6 || ip.Is6()
	}
	if hasV4 {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if hasV6 {
		t.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	t.events <- tun.EventUp
	return t, nil
}

func (t *netTUN) Name() (string, error)    { return "go", nil }
func (t *netTUN) File() *os.File           { return nil }
func (t *netTUN) Events() <-chan tun.Event { return t.events }
func (t *netTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *netTUN) BatchSize() int           { return 1 }

// Read hands amneziawg-go the next outbound packet, or os.ErrClosed once
// the device is closed — which is what ends its RoutineReadFromTUN.
func (t *netTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case view := <-t.incoming:
		n, err := view.Read(bufs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

// Write injects decrypted inbound packets into the stack.
func (t *netTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(bufs), nil
}

// WriteNotify is gVisor telling us the stack queued an outbound packet. It
// runs on whatever goroutine produced the packet — a dialer, a TCP timer, a
// processor answering a late segment with an RST — at any time, including
// during and after Close. Hence the select: once done is closed the packet
// is dropped instead of being sent on a channel nobody reads.
func (t *netTUN) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case t.incoming <- view:
	case <-t.done:
		view.Release()
	}
}

// Close shuts the stack down and waits for its goroutines. It is
// idempotent. incoming is deliberately never closed (see netTUN); events
// is, because amneziawg-go ranges over it and nothing sends on it after
// newNetTUN.
func (t *netTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		t.stack.RemoveNIC(nicID)
		t.stack.Close()
		t.ep.RemoveNotify(t.notifyHandle)
		t.ep.Close()
		t.stack.Wait()
		close(t.events)
	})
	return nil
}

// DialContext opens a TCP connection to an IP:port inside the tunnel. A
// host name is refused rather than resolved: the stack has no resolver on
// purpose (spec §4), and the probe URL names mon-server by address.
func (t *netTUN) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("tunnel dials IP:port only: %w", err)}
	}
	fa, proto := fullAddr(ap)
	c, err := gonet.DialContextTCP(ctx, t.stack, fa, proto)
	if err != nil {
		// Not `return gonet.DialContextTCP(...)`: a nil *gonet.TCPConn
		// would come back as a non-nil net.Conn.
		return nil, err
	}
	return c, nil
}

// fullAddr converts an address to gVisor's form on the one NIC.
func fullAddr(ap netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := tcpip.NetworkProtocolNumber(ipv4.ProtocolNumber)
	if ap.Addr().Is6() && !ap.Addr().Is4In6() {
		proto = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ap.Addr().Unmap().AsSlice()),
		Port: ap.Port(),
	}, proto
}
