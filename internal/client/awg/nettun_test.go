package awg

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNetTUNCloseWithBlockedWriteNotify is #69: gVisor calls WriteNotify
// from its own goroutines at any time, and amneziawg-go's netstack Close
// closed the channel WriteNotify sends on — a sender parked there turned
// Close into "send on closed channel", a panic of the whole mon-client
// (and a data race under -race when the send merely overlapped).
//
// The test parks a sender deterministically: a dial makes the stack emit a
// SYN, nobody reads the device, so WriteNotify blocks on its send. Close
// must then return, release the sender and leave Read reporting
// os.ErrClosed.
func TestNetTUNCloseWithBlockedWriteNotify(t *testing.T) {
	tn, err := newNetTUN([]netip.Addr{netip.MustParseAddr(clientTunnelIP)}, 1420)
	if err != nil {
		t.Fatalf("newNetTUN: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dialed := make(chan error, 1)
	go func() {
		c, err := tn.DialContext(ctx, "tcp", netip.AddrPortFrom(netip.MustParseAddr(serverTunnelIP), serverPort).String())
		if c != nil {
			_ = c.Close()
		}
		dialed <- err
	}()
	waitForGoroutineIn(t, "(*netTUN).WriteNotify")

	closed := make(chan struct{})
	go func() {
		_ = tn.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return with a sender parked in WriteNotify")
	}
	select {
	case err := <-dialed:
		if err == nil {
			t.Error("dial succeeded through a device nobody ever read")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dial was still stuck after Close")
	}

	if _, err := tn.Read([][]byte{make([]byte, 1500)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read after Close = %v, want os.ErrClosed", err)
	}
	// A late packet after Close — what gVisor's RST reply to a straggling
	// segment was — is dropped, not sent on anything.
	tn.WriteNotify()
	if err := tn.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

// waitForGoroutineIn waits until some goroutine's stack contains frame.
// It is how the test knows the sender is really parked before it closes
// the device, without a sleep that a loaded CI box could outrun.
func waitForGoroutineIn(t *testing.T, frame string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		if strings.Contains(string(buf[:n]), frame) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no goroutine reached %s", frame)
}
