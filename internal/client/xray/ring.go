// Package xray owns mon-client's child xray process (spec §8, adapted to the
// shared module as internal/client/xray): validating a generated config with
// `xray -test` before it is applied, starting and restarting the child
// between probe cycles, and reading its stderr into a ring buffer so a failed
// probe can be explained with the line xray itself printed (spec §4 step 3,
// §5).
//
// The package deliberately knows nothing about the protocol, the config
// generator or the probe: it takes a binary path and a config file path and
// hands back process control plus a pure log matcher (Diagnose), so every
// behaviour here can be tested against a fake xray instead of the real one.
package xray

import (
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// RingLines is how many stderr lines mon-client keeps from the child xray
// (spec §5: "кольцевой буфер последних 500 строк с временем"). It is a
// window, not a log: a probe only ever looks at the lines written inside its
// own budget, and 500 lines comfortably covers a cycle's worth of dial and
// Reality chatter for every target while keeping the buffer bounded on a box
// where xray is noisy.
const RingLines = 500

// Line is one line of the child's stderr together with the time mon-client
// read it. The timestamp is mon-client's, not xray's: matching a probe to the
// lines it caused (Diagnose) compares against the probe's own window, so the
// two must come from the same clock (spec §5).
type Line struct {
	At   time.Time
	Text string
}

// Ring is the fixed-size stderr window of the child xray. It is written by
// the stderr reader goroutine and read by probes while they run, so every
// method is safe for concurrent use; Snapshot copies, because a caller that
// ranged over the live buffer would race the reader.
type Ring struct {
	mu   sync.Mutex
	clk  clock.Clock
	buf  []Line
	next int  // index of the next slot to write
	full bool // whether the buffer has wrapped at least once
}

// NewRing returns a Ring holding the last n lines, stamped with real time.
// Callers that need deterministic timestamps in tests use NewRingWithClock.
func NewRing(n int) *Ring { return NewRingWithClock(n, clock.Real{}) }

// NewRingWithClock is NewRing with the clock injected: mon-client reads the
// time only through clock.Clock (brief §1), and a test that asserts on the
// window Diagnose sees needs to own the timestamps.
func NewRingWithClock(n int, clk clock.Clock) *Ring {
	if n <= 0 {
		n = RingLines
	}
	return &Ring{clk: clk, buf: make([]Line, n)}
}

// Append stores l, evicting the oldest line once the buffer is full.
func (r *Ring) Append(l Line) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = l
	r.next++
	if r.next == len(r.buf) {
		r.next = 0
		r.full = true
	}
}

// AppendText stamps text with the ring's clock and appends it. This is what
// the stderr reader uses: the read time is the only timestamp mon-client can
// trust, since xray's own prefix is formatted in the container's local zone.
func (r *Ring) AppendText(text string) {
	r.Append(Line{At: r.clk.Now(), Text: text})
}

// Snapshot returns the buffered lines oldest first, as a copy the caller may
// keep: Diagnose is pure and runs on the snapshot while xray keeps writing.
func (r *Ring) Snapshot() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]Line, r.next)
		copy(out, r.buf[:r.next])
		return out
	}
	out := make([]Line, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}
