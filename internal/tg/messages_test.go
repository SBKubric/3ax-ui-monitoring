package tg

import (
	"strings"
	"testing"
	"time"
)

// TestMsgConfigError checks spec §8's exact wording and the first-line/256
// rune trimming rule (deliverable §3.2: "config error uses the first line
// only, ≤ 256 runes — trim").
func TestMsgConfigError(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "single line",
			raw:  "dial tcp: connection refused",
			want: "mon-client ams-1: config error dial tcp: connection refused",
		},
		{
			name: "multi line uses only the first",
			raw:  "bad config\nstack trace line 2\nstack trace line 3",
			want: "mon-client ams-1: config error bad config",
		},
		{
			name: "crlf first line",
			raw:  "bad config\r\nsecond line",
			want: "mon-client ams-1: config error bad config",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MsgConfigError("ams-1", tc.raw); got != tc.want {
				t.Fatalf("MsgConfigError = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMsgConfigError_TrimsTo256Runes checks the length cap itself, using
// multi-byte runes so a byte-based truncation (which would be wrong) is
// distinguishable from a rune-based one.
func TestMsgConfigError_TrimsTo256Runes(t *testing.T) {
	long := strings.Repeat("é", 300) // 300 runes, 600 bytes in UTF-8
	got := MsgConfigError("ams-1", long)

	const prefix = "mon-client ams-1: config error "
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("MsgConfigError = %q, want prefix %q", got, prefix)
	}
	excerpt := []rune(strings.TrimPrefix(got, prefix))
	if len(excerpt) != configErrorMaxRunes {
		t.Fatalf("excerpt length = %d runes, want %d", len(excerpt), configErrorMaxRunes)
	}
}

// TestMsgTargetTransition checks spec §4.1/§8's exact wording and mark for
// a target transition sent while PANEL_DOWN.
func TestMsgTargetTransition(t *testing.T) {
	got := MsgTargetTransition("ams-1", "NL", "xray", 12, "proxy", "UP", "DOWN", "tls_timeout")
	want := "[via mon-server] target ams-1 (NL) xray:12/proxy UP → DOWN (tls_timeout)"
	if got != want {
		t.Fatalf("MsgTargetTransition = %q, want %q", got, want)
	}
}

// TestMsgMonClientTransition checks spec §4.1/§8's exact wording and mark
// for a mon-client transition sent while PANEL_DOWN.
func TestMsgMonClientTransition(t *testing.T) {
	got := MsgMonClientTransition("ams-1", "NL", "ONLINE", "OFFLINE")
	want := "[via mon-server] mon-client ams-1 (NL) ONLINE → OFFLINE"
	if got != want {
		t.Fatalf("MsgMonClientTransition = %q, want %q", got, want)
	}
}

// TestMsgTargetRecovered checks spec §7.2's "UP" row: the recovery message
// carries the downtime, rounded to whole seconds, and is only ever used for
// a transition out of DOWN — which is why the states are baked into the
// text rather than passed in.
func TestMsgTargetRecovered(t *testing.T) {
	cases := []struct {
		name     string
		downtime time.Duration
		want     string
	}{
		{
			name:     "minutes and seconds",
			downtime: 12*time.Minute + 30*time.Second,
			want:     "[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 12m30s",
		},
		{
			name:     "rounded to whole seconds",
			downtime: 45*time.Second + 600*time.Millisecond,
			want:     "[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 46s",
		},
		{
			name:     "hours",
			downtime: 3*time.Hour + 4*time.Minute + 5*time.Second,
			want:     "[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 3h4m5s",
		},
		{
			name:     "zero",
			downtime: 0,
			want:     "[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 0s",
		},
		{
			name:     "negative is shown as zero",
			downtime: -time.Minute,
			want:     "[via mon-server] target ams-1 (NL) xray:12/proxy DOWN → UP after 0s",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MsgTargetRecovered("ams-1", "NL", "xray", 12, "proxy", tc.downtime)
			if got != tc.want {
				t.Fatalf("MsgTargetRecovered = %q, want %q", got, tc.want)
			}
		})
	}
}
