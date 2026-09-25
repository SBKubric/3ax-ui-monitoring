// Package awg probes an AmneziaWG target from inside this process: every
// probe builds a fresh gVisor netstack device from the target's `.conf`,
// dials mon-server's tunnel probe through it and reports how long the AWG
// handshake, the TCP connect, the TLS handshake and the first byte took
// (spec §5, research §3.4, §6.2).
//
// Nothing here touches the kernel: no TUN interface, no route, no
// capability. That is the whole reason netstack was chosen over a real
// interface — a mon-client may watch a dozen AWG targets on one box and
// must not need NET_ADMIN to do it (research §3.4, §4).
package awg

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
)

// handshakeFailureMark is the substring amneziawg-go logs when an
// initiation goes unanswered ("Handshake did not complete after 5 seconds,
// retrying (try 2)", research §3.5). WireGuard has no handshake *error* —
// an unauthorised or unreachable peer simply never replies — so these lines
// are the only human-readable evidence a failed probe can carry as its
// `detail` (spec §5, reason awg_no_handshake).
const handshakeFailureMark = "Handshake did not complete"

// logRingSize is how many handshake-failure lines one probe keeps. A probe
// lasts a few seconds and amneziawg-go retries every 5 s (research §3.5),
// so a handful is already more than one probe can produce; the ring only
// exists so a pathological device cannot grow memory without bound.
const logRingSize = 8

// Device is one live netstack AWG tunnel: the gVisor stack, the
// amneziawg-go device driving it, and the handshake-failure lines the
// device logged while it was up.
//
// It is deliberately single-use. Keeping a device alive across probes would
// mean a handshake is only re-done every 120 s (RekeyAfterTime), so four of
// five probes could not measure one at all; recreating it per probe costs a
// single initiation plus Jc junk packets a minute and buys a handshake
// measurement every cycle (research §3.6, spec §5).
type Device struct {
	dev  *device.Device
	tun  *netTUN
	ring *logRing
}

// Open brings up a fresh netstack device for cfg: a netTUN with the
// `.conf`'s addresses and MTU (our copy of amneziawg-go's CreateNetTUN —
// see netTUN for why), NewDevice on a batch-1 UDP bind (probeBind — see
// there why not the default one), IpcSet with the UAPI blob
// internal/client/config already rendered in IpcSet order, then Up
// (research §3.4).
//
// The stack has no DNS resolver: mon-client always dials mon-server by
// address, never by name (spec §4), so a resolver inside the tunnel would
// only add a failure mode.
func Open(cfg *config.AWGConfig) (*Device, error) {
	if cfg == nil {
		return nil, fmt.Errorf("awg: no config")
	}
	ring := &logRing{}
	tun, err := newNetTUN(cfg.LocalAddresses, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("awg: create netstack tun: %w", err)
	}
	dev := newDevice(tun, ring.logger())
	if err := dev.IpcSet(cfg.UAPI); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg: apply uapi config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("awg: bring device up: %w", err)
	}
	return &Device{dev: dev, tun: tun, ring: ring}, nil
}

// newDevice is the one way this package builds an amneziawg-go device, so
// Check judges a config on the very device Open would run it on: netTUN
// underneath, probeBind for the UDP side.
func newDevice(tun *netTUN, log *device.Logger) *device.Device {
	return device.NewDevice(tun, newProbeBind(), log)
}

// DialContext opens a TCP connection through the tunnel. It is the
// http.Transport's dialer as well as the probe's own connect measurement:
// httptrace's ConnectStart/ConnectDone never fire for a custom dialer,
// because net.Dialer is what reads the trace out of the context and gVisor
// does not (research §6.2).
func (d *Device) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tun.DialContext(ctx, network, address)
}

// LastHandshake reports the newest peer handshake the device knows about,
// parsed out of the UAPI `get=1` dump (`last_handshake_time_sec` /
// `_nsec`). ok is false while no peer has ever completed one — UAPI spells
// that as a zero timestamp, and it is exactly the awg_no_handshake
// condition of spec §5.
//
// The newest of all peers is taken because a `.conf` may list several and
// any one of them completing means the tunnel carries traffic.
func (d *Device) LastHandshake() (t time.Time, ok bool) {
	dump, err := d.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	return parseLastHandshake(dump)
}

// HandshakeFailures returns the handshake-failure lines the device logged,
// newest last, joined for use as a Result.Detail (spec §5).
func (d *Device) HandshakeFailures() string {
	return strings.Join(d.ring.lines(), "; ")
}

// Close tears the device and its netstack down. It is safe to call twice,
// which matters because every probe defers it (spec §5: the device must go
// away even when the probe failed half way).
func (d *Device) Close() {
	if d == nil || d.dev == nil {
		return
	}
	d.dev.Close()
	d.dev = nil
}

// parseLastHandshake reads the newest last_handshake_time out of a UAPI
// get=1 dump. Kept separate from LastHandshake so it can be tested without
// a device.
func parseLastHandshake(dump string) (time.Time, bool) {
	var sec, nsec int64
	var best time.Time
	var ok bool
	flush := func() {
		if sec == 0 && nsec == 0 {
			return
		}
		if t := time.Unix(sec, nsec); !ok || t.After(best) {
			best, ok = t, true
		}
	}
	for _, line := range strings.Split(dump, "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "public_key":
			// A new peer block starts: bank whatever the previous
			// one reported before its fields are overwritten.
			flush()
			sec, nsec = 0, 0
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	flush()
	return best, ok
}

// logRing is the device.Logger adapter: it keeps the last few
// handshake-failure lines and throws the rest of amneziawg-go's very
// chatty verbose output away. mon-client's own log is slog on stdout
// (spec §7); the device's log exists only to give a failed probe a
// `detail`.
type logRing struct {
	mu   sync.Mutex
	buf  [logRingSize]string
	n    int
	next int
}

// logger hands amneziawg-go a Logger whose two levels both funnel into the
// ring. Both are set (rather than only Errorf) because "Handshake did not
// complete" is a *verbose* line in amneziawg-go, not an error one.
func (r *logRing) logger() *device.Logger {
	record := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		if strings.Contains(line, handshakeFailureMark) {
			r.append(line)
		}
	}
	return &device.Logger{Verbosef: record, Errorf: record}
}

func (r *logRing) append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = line
	r.next = (r.next + 1) % logRingSize
	if r.n < logRingSize {
		r.n++
	}
}

// lines returns the recorded lines oldest first.
func (r *logRing) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, r.n)
	start := (r.next - r.n + logRingSize) % logRingSize
	for i := 0; i < r.n; i++ {
		out = append(out, r.buf[(start+i)%logRingSize])
	}
	return out
}
