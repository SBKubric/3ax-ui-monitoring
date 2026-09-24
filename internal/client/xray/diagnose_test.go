package xray

import (
	"strings"
	"testing"
	"time"
)

// The samples are the real lines from research §2.4 (Xray 26.3.27, loglevel
// info, an outbound pointed at www.cloudflare.com:443 with a foreign pbk).
const (
	sampleDial     = `2026/09/12 15:44:06.500000 [Info] [1645185437] transport/internet/tcp: dialing TCP to tcp:www.cloudflare.com:443`
	sampleReality  = `2026/09/12 15:44:06.887083 [Error] [1645185437] transport/internet/reality: REALITY: received real certificate (potential MITM or redirection)`
	sampleRetry    = `2026/09/12 15:44:07.487999 [Info] [1645185437] transport/internet/tcp: dialing TCP to tcp:www.cloudflare.com:443`
	sampleFailed   = `2026/09/12 15:44:08.397455 [Info] [1645185437] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [transport/internet/reality: REALITY: processed invalid connection] > common/retry: all retry attempts failed`
	otherDial      = `2026/09/12 15:44:06.500000 [Info] [77] transport/internet/tcp: dialing TCP to tcp:example.org:8443`
	otherFailed    = `2026/09/12 15:44:08.397455 [Info] [77] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > common/retry: all retry attempts failed`
	sampleDialIP   = `2026/09/12 15:45:57.745131 [Info] [999] transport/internet/tcp: dialing TCP to tcp:10.255.255.1:443`
	sampleFailedIP = `2026/09/12 15:46:29.955156 [Info] [999] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [dial tcp 10.255.255.1:443: i/o timeout] > common/retry: all retry attempts failed`
)

// TestDiagnose walks the stderr matching rules of spec §5 on the research
// §2.4 samples: only lines of a session that dialled this target inside the
// probe window may explain the probe.
func TestDiagnose(t *testing.T) {
	base := time.Date(2026, 9, 12, 15, 44, 6, 0, time.UTC)
	at := func(ms int) time.Time { return base.Add(time.Duration(ms) * time.Millisecond) }
	since, until := at(0), at(5000)

	lines := func(texts ...string) []Line {
		out := make([]Line, 0, len(texts))
		for i, tx := range texts {
			out = append(out, Line{At: at(i * 500), Text: tx})
		}
		return out
	}

	longLine := `2026/09/12 15:44:08.397455 [Info] [1645185437] app/proxyman/outbound: failed to process outbound traffic > ` + strings.Repeat("x", 400)

	cases := []struct {
		name       string
		lines      []Line
		addr       string
		port       int
		since      time.Time
		until      time.Time
		wantOK     bool
		wantReason string
		wantDetail string
	}{
		{
			name:       "reality real certificate",
			lines:      lines(sampleDial, sampleReality, sampleRetry, sampleFailed),
			addr:       "www.cloudflare.com",
			port:       443,
			since:      since,
			until:      until,
			wantOK:     true,
			wantReason: ReasonRealityRealCert,
			// The real line is longer than the 256-rune cap of spec §5.
			wantDetail: trimDetail("app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [transport/internet/reality: REALITY: processed invalid connection] > common/retry: all retry attempts failed"),
		},
		{
			name:       "reality line alone (loglevel warning)",
			lines:      lines(sampleDial, sampleReality),
			addr:       "www.cloudflare.com",
			port:       443,
			since:      since,
			until:      until,
			wantOK:     true,
			wantReason: ReasonRealityRealCert,
			wantDetail: "transport/internet/reality: REALITY: received real certificate (potential MITM or redirection)",
		},
		{
			name:       "dead address, no reason but a detail",
			lines:      lines(sampleDialIP, sampleFailedIP),
			addr:       "10.255.255.1",
			port:       443,
			since:      since,
			until:      until,
			wantOK:     true,
			wantReason: "",
			wantDetail: trimDetail("app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [dial tcp 10.255.255.1:443: i/o timeout] > common/retry: all retry attempts failed"),
		},
		{
			name:   "another target's session is ignored",
			lines:  lines(otherDial, otherFailed),
			addr:   "www.cloudflare.com",
			port:   443,
			since:  since,
			until:  until,
			wantOK: false,
		},
		{
			name:   "same host, another port",
			lines:  lines(sampleDial, sampleReality, sampleFailed),
			addr:   "www.cloudflare.com",
			port:   8443,
			since:  since,
			until:  until,
			wantOK: false,
		},
		{
			name:   "same port, another host",
			lines:  lines(sampleDial, sampleReality, sampleFailed),
			addr:   "example.org",
			port:   443,
			since:  since,
			until:  until,
			wantOK: false,
		},
		{
			name:   "dial before the probe window",
			lines:  lines(sampleDial, sampleReality, sampleFailed),
			addr:   "www.cloudflare.com",
			port:   443,
			since:  at(2000),
			until:  at(5000),
			wantOK: false,
		},
		{
			name:   "dial after the probe window",
			lines:  lines(sampleDial, sampleReality, sampleFailed),
			addr:   "www.cloudflare.com",
			port:   443,
			since:  since,
			until:  at(100),
			wantOK: false,
		},
		{
			name:   "a successful probe has nothing to explain",
			lines:  lines(sampleDial, sampleRetry),
			addr:   "www.cloudflare.com",
			port:   443,
			since:  since,
			until:  until,
			wantOK: false,
		},
		{
			name:   "empty buffer",
			lines:  nil,
			addr:   "www.cloudflare.com",
			port:   443,
			since:  since,
			until:  until,
			wantOK: false,
		},
		{
			name:       "detail is capped at 256 runes",
			lines:      lines(sampleDial, longLine),
			addr:       "www.cloudflare.com",
			port:       443,
			since:      since,
			until:      until,
			wantOK:     true,
			wantReason: "",
			wantDetail: ("app/proxyman/outbound: failed to process outbound traffic > " + strings.Repeat("x", 400))[:maxDetail],
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Diagnose(tc.lines, Target{OutboundTag: "out-xray-12-proxy", Addr: tc.addr, Port: tc.port}, tc.since, tc.until)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (match %+v)", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Detail != tc.wantDetail {
				t.Errorf("detail =\n%q\nwant\n%q", got.Detail, tc.wantDetail)
			}
			if len([]rune(got.Detail)) > maxDetail {
				t.Errorf("detail is %d runes, want ≤ %d", len([]rune(got.Detail)), maxDetail)
			}
		})
	}
}

// TestDiagnoseMatchesIPv6AndBareForm proves the address comparison is
// value-wise for IPs (so a target written as ::1 matches xray's [::1]) and
// that a destination without xray's "tcp:" prefix still matches.
func TestDiagnoseMatchesIPv6AndBareForm(t *testing.T) {
	base := time.Date(2026, 9, 12, 15, 44, 6, 0, time.UTC)
	lines := []Line{
		{At: base, Text: `2026/09/12 15:44:06.500000 [Info] [42] transport/internet/tcp: dialing TCP to [::1]:443`},
		{At: base.Add(time.Second), Text: `2026/09/12 15:44:07.500000 [Error] [42] transport/internet/reality: REALITY: received real certificate (potential MITM or redirection)`},
	}
	got, ok := Diagnose(lines, Target{Addr: "::1", Port: 443}, base, base.Add(5*time.Second))
	if !ok {
		t.Fatalf("no match for ::1")
	}
	if got.Reason != ReasonRealityRealCert {
		t.Errorf("reason = %q, want %q", got.Reason, ReasonRealityRealCert)
	}
}

// Lines of two targets whose outbounds dial the same real server
// (10.255.255.1:443) — the shape decision #53 п. 6 allows. The detour and
// dial lines are in the exact format Xray 26.3.27 writes at loglevel info,
// checked on 2026-09-24 against ghcr.io/xtls/xray-core:26.3.27 with two
// socks inbounds routed to two vless outbounds on one address: the
// dispatcher names the outbound tag under the session id before the
// transport dials, e.g.
//
//	[Info] [3391315677] app/dispatcher: taking detour [out-xray-12-proxy] for [tcp:mon.example:443]
//	[Info] [3391315677] transport/internet/tcp: dialing TCP to tcp:10.255.255.1:443
const (
	detourA  = `2026/09/24 02:16:20.053614 [Info] [3391315677] app/dispatcher: taking detour [out-xray-12-proxy] for [tcp:mon.example:443]`
	detourB  = `2026/09/24 02:16:20.053621 [Info] [1425586641] app/dispatcher: taking detour [out-xray-13-proxy] for [tcp:mon.example:443]`
	dialA    = `2026/09/24 02:16:20.053627 [Info] [3391315677] transport/internet/tcp: dialing TCP to tcp:10.255.255.1:443`
	dialB    = `2026/09/24 02:16:20.053624 [Info] [1425586641] transport/internet/tcp: dialing TCP to tcp:10.255.255.1:443`
	realityA = `2026/09/24 02:16:20.300000 [Error] [3391315677] transport/internet/reality: REALITY: received real certificate (potential MITM or redirection)`
	failedA  = `2026/09/24 02:16:21.000000 [Info] [3391315677] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > common/retry: [transport/internet/reality: REALITY: processed invalid connection] > common/retry: all retry attempts failed`
	failedB  = `2026/09/24 02:16:22.000000 [Info] [1425586641] app/proxyman/outbound: app/proxyman/outbound: failed to process outbound traffic > common/retry: [dial tcp 10.255.255.1:443: i/o timeout] > common/retry: all retry attempts failed`
)

// TestDiagnoseByOutboundTag is decision #53 п. 6: two targets may share a
// real server's addr:port, so a session is attributed to a target by the
// outbound tag the dispatcher's "taking detour" line names, and addr:port
// is only the fallback. Matching on addr:port alone gives both targets the
// Reality certificate that only one of them received.
func TestDiagnoseByOutboundTag(t *testing.T) {
	base := time.Date(2026, 9, 24, 2, 16, 20, 0, time.UTC)
	lines := make([]Line, 0, 7)
	for i, tx := range []string{detourA, detourB, dialB, dialA, realityA, failedA, failedB} {
		lines = append(lines, Line{At: base.Add(time.Duration(i) * 100 * time.Millisecond), Text: tx})
	}
	since, until := base, base.Add(5*time.Second)

	a, ok := Diagnose(lines, Target{OutboundTag: "out-xray-12-proxy", Addr: "10.255.255.1", Port: 443}, since, until)
	if !ok {
		t.Fatal("target A: no match")
	}
	if a.Reason != ReasonRealityRealCert {
		t.Errorf("target A reason = %q, want %q", a.Reason, ReasonRealityRealCert)
	}
	if !strings.Contains(a.Detail, "REALITY: processed invalid connection") {
		t.Errorf("target A detail = %q, want its own failed-outbound line", a.Detail)
	}

	b, ok := Diagnose(lines, Target{OutboundTag: "out-xray-13-proxy", Addr: "10.255.255.1", Port: 443}, since, until)
	if !ok {
		t.Fatal("target B: no match")
	}
	if b.Reason != "" {
		t.Errorf("target B reason = %q, want none: the real certificate was A's", b.Reason)
	}
	if !strings.Contains(b.Detail, "i/o timeout") {
		t.Errorf("target B detail = %q, want its own failed-outbound line", b.Detail)
	}

	// A third target on the same server that xray never routed anything to
	// in the window has nothing to explain: the fallback must not hand it
	// sessions the detour lines already gave to A and B.
	if m, ok := Diagnose(lines, Target{OutboundTag: "out-xray-14-proxy", Addr: "10.255.255.1", Port: 443}, since, until); ok {
		t.Errorf("target C matched %+v, want nothing", m)
	}
}

// TestDiagnoseFallsBackToAddrPort: when the window holds no detour line for
// the target's tag (a log format change, a lower loglevel), the session is
// still found by its dial line, as before decision #53.
func TestDiagnoseFallsBackToAddrPort(t *testing.T) {
	base := time.Date(2026, 9, 24, 2, 16, 20, 0, time.UTC)
	lines := []Line{
		{At: base, Text: dialA},
		{At: base.Add(100 * time.Millisecond), Text: realityA},
	}
	m, ok := Diagnose(lines, Target{OutboundTag: "out-xray-12-proxy", Addr: "10.255.255.1", Port: 443}, base, base.Add(time.Second))
	if !ok || m.Reason != ReasonRealityRealCert {
		t.Fatalf("Diagnose = %+v, %v; want the Reality line through the addr:port fallback", m, ok)
	}
}
