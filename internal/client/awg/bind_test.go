package awg

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

// TestOpenUsesProbeBind pins #90 where it is decided: a probe device runs
// on the batch-1 probeBind, not on conn.NewDefaultBind(), whose 128-packet
// batches cost ~25 MB of buffers per device (#85).
func TestOpenUsesProbeBind(t *testing.T) {
	d, err := Open(confFor(t, "203.0.113.7:51820", ""))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()
	b, ok := d.dev.Bind().(*probeBind)
	if !ok {
		t.Fatalf("device bind is %T, want *probeBind", d.dev.Bind())
	}
	if got := b.BatchSize(); got != 1 {
		t.Errorf("BatchSize() = %d, want 1", got)
	}
}

// TestProbeBindRoundTrip sends datagrams between two binds over loopback,
// on IPv4 and on IPv6: one dual-stack socket must serve a peer endpoint of
// either family, and a received endpoint must read as the plain address
// the UAPI dump and the handshake's mac2 cookie expect (never the
// v4-mapped form a dual-stack socket reports IPv4 senders in).
func TestProbeBindRoundTrip(t *testing.T) {
	for _, loopback := range []string{"127.0.0.1", "::1"} {
		t.Run(loopback, func(t *testing.T) {
			if loopback == "::1" {
				requireIPv6Loopback(t)
			}
			a, _, aPort := openBind(t)
			_, bRecv, bPort := openBind(t)

			toB, err := a.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr(loopback), bPort).String())
			if err != nil {
				t.Fatalf("ParseEndpoint: %v", err)
			}
			// Several buffers in one Send: amneziawg-go hands the Jc junk
			// packets and the initiation over together, whatever
			// BatchSize says.
			sent := []string{"junk", "initiation"}
			if err := a.Send([][]byte{[]byte(sent[0]), []byte(sent[1])}, toB); err != nil {
				t.Fatalf("Send: %v", err)
			}
			for _, want := range sent {
				got, from := receiveOne(t, bRecv)
				if got != want {
					t.Errorf("received %q, want %q", got, want)
				}
				wantFrom := netip.AddrPortFrom(netip.MustParseAddr(loopback), aPort)
				if from.DstToString() != wantFrom.String() {
					t.Errorf("sender endpoint = %s, want %s", from.DstToString(), wantFrom)
				}
				if from.DstIP() != wantFrom.Addr() {
					t.Errorf("sender DstIP = %s, want %s", from.DstIP(), wantFrom.Addr())
				}
				wantBytes, _ := wantFrom.MarshalBinary()
				if string(from.DstToBytes()) != string(wantBytes) {
					t.Errorf("sender DstToBytes = %x, want %x", from.DstToBytes(), wantBytes)
				}
			}
		})
	}
}

// TestProbeBindLifecycle walks the order amneziawg-go drives a bind in:
// BindUpdate closes before it opens, Close runs again on device Close, and
// a device brought down and up again reopens the same bind.
func TestProbeBindLifecycle(t *testing.T) {
	b := newProbeBind()
	if err := b.Close(); err != nil {
		t.Fatalf("Close of a never opened bind: %v", err)
	}

	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open(0): %v", err)
	}
	if port == 0 {
		t.Error("Open(0) reported port 0, want the port the kernel picked")
	}
	if len(fns) != 1 {
		t.Errorf("Open returned %d receive functions, want 1 (one dual-stack socket)", len(fns))
	}
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Errorf("second Open: err = %v, want ErrBindAlreadyOpen", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	bufs, sizes, eps := [][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)
	if _, err := fns[0](bufs, sizes, eps); !errors.Is(err, net.ErrClosed) {
		t.Errorf("receive after Close: err = %v, want net.ErrClosed (it ends RoutineReceiveIncoming)", err)
	}
	ep, err := b.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if err := b.Send([][]byte{[]byte("x")}, ep); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Send after Close: err = %v, want net.ErrClosed", err)
	}

	if _, _, err := b.Open(port); err != nil {
		t.Fatalf("reopen on port %d: %v", port, err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close after reopen: %v", err)
	}
}

func TestProbeBindParseEndpoint(t *testing.T) {
	b := newProbeBind()
	for _, tc := range []struct {
		in, want string
	}{
		{"192.0.2.1:51820", "192.0.2.1:51820"},
		{"[2001:db8::1]:51820", "[2001:db8::1]:51820"},
		// UAPI may hand an IPv4 peer over in its v4-mapped spelling;
		// it is the same peer and must print like it.
		{"[::ffff:192.0.2.1]:51820", "192.0.2.1:51820"},
	} {
		ep, err := b.ParseEndpoint(tc.in)
		if err != nil {
			t.Errorf("ParseEndpoint(%q): %v", tc.in, err)
			continue
		}
		if got := ep.DstToString(); got != tc.want {
			t.Errorf("ParseEndpoint(%q).DstToString() = %q, want %q", tc.in, got, tc.want)
		}
		if ep.SrcToString() != "" || ep.SrcIP().IsValid() {
			t.Errorf("ParseEndpoint(%q) has a source address; the probe bind never pins one", tc.in)
		}
	}
	for _, bad := range []string{"", "192.0.2.1", "example.com:51820", "192.0.2.1:port"} {
		if _, err := b.ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) succeeded, want an error", bad)
		}
	}
}

func TestProbeBindSendRejectsForeignEndpoint(t *testing.T) {
	b, _, _ := openBind(t)
	foreign, err := conn.NewStdNetBind().ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if err := b.Send([][]byte{[]byte("x")}, foreign); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Errorf("Send to a %T: err = %v, want ErrWrongEndpointType", foreign, err)
	}
}

// openBind opens a probeBind on a kernel-chosen port for the length of the
// test.
func openBind(t *testing.T) (*probeBind, conn.ReceiveFunc, uint16) {
	t.Helper()
	b := newProbeBind()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open(0): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, fns[0], port
}

// receiveOne reads one datagram, failing the test instead of hanging when
// nothing arrives.
func receiveOne(t *testing.T, recv conn.ReceiveFunc) (string, conn.Endpoint) {
	t.Helper()
	type packet struct {
		data string
		from conn.Endpoint
		err  error
	}
	got := make(chan packet, 1)
	go func() {
		bufs, sizes, eps := [][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1)
		n, err := recv(bufs, sizes, eps)
		if err == nil && n != 1 {
			err = errors.New("receive returned no packet")
		}
		if err != nil {
			got <- packet{err: err}
			return
		}
		got <- packet{data: string(bufs[0][:sizes[0]]), from: eps[0]}
	}()
	select {
	case p := <-got:
		if p.err != nil {
			t.Fatalf("receive: %v", p.err)
		}
		return p.data, p.from
	case <-time.After(10 * time.Second):
		t.Fatal("no datagram within 10s")
		return "", nil
	}
}

// requireIPv6Loopback skips when the box (a CI container, say) has no ::1.
func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = c.Close()
}
