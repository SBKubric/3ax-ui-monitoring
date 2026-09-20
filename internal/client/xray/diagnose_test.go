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
			got, ok := Diagnose(tc.lines, tc.addr, tc.port, tc.since, tc.until)
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
	got, ok := Diagnose(lines, "::1", 443, base, base.Add(5*time.Second))
	if !ok {
		t.Fatalf("no match for ::1")
	}
	if got.Reason != ReasonRealityRealCert {
		t.Errorf("reason = %q, want %q", got.Reason, ReasonRealityRealCert)
	}
}
