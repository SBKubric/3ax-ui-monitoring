package awg

// THROWAWAY PROTOTYPE (leak investigation): a batch-1 single-socket Bind.

import (
	"net"
	"net/netip"
	"os"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type bind1 struct{ c *net.UDPConn }

type ep1 struct{ ap netip.AddrPort }

func (e *ep1) ClearSrc()           {}
func (e *ep1) SrcToString() string { return "" }
func (e *ep1) DstToString() string { return e.ap.String() }
func (e *ep1) DstToBytes() []byte  { b, _ := e.ap.MarshalBinary(); return b }
func (e *ep1) DstIP() netip.Addr   { return e.ap.Addr() }
func (e *ep1) SrcIP() netip.Addr   { return netip.Addr{} }

func (b *bind1) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := c.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &ep1{ap: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *bind1) Close() error {
	if b.c != nil {
		return b.c.Close()
	}
	return nil
}
func (b *bind1) SetMark(uint32) error { return nil }
func (b *bind1) Send(bufs [][]byte, e conn.Endpoint) error {
	ap := e.(*ep1).ap
	for _, buf := range bufs {
		if _, err := b.c.WriteToUDPAddrPort(buf, ap); err != nil {
			return err
		}
	}
	return nil
}
func (b *bind1) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &ep1{ap: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}
func (b *bind1) BatchSize() int { return 1 }

func newBind() conn.Bind {
	if os.Getenv("LEAK_BIND1") != "" {
		return &bind1{}
	}
	return conn.NewDefaultBind()
}
