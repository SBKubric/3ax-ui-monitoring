// Package clock is the one place mon-server is allowed to ask what time it
// is. Every other package takes a Clock instead of calling time.Now(), so
// tests can drive state machines, timeouts and retention jobs from a Fake
// clock instead of racing the wall clock (docs/agents/testing.md: no
// sleep-and-hope tests).
package clock

import (
	"sync"
	"time"
)

// Clock is the seam between "what time is it" and everything that depends on
// the answer. Production code takes a Clock, never time.Now(), so a test can
// swap in Fake and get a deterministic minute-by-minute simulation of the
// panel poll, heartbeat timeouts and the state machine.
type Clock interface {
	// Now returns the current time. Real returns UTC wall-clock time; Fake
	// returns whatever it was last told.
	Now() time.Time
}

// Real is the production Clock: a thin wrapper over time.Now(), always
// normalised to UTC because every stored timestamp in mon-server is ms UTC
// epoch (spec §3: "Времена — ms UTC") and mixing zones into that would be a
// bug waiting to happen.
type Real struct{}

// Now returns time.Now() in UTC.
func (Real) Now() time.Time { return time.Now().UTC() }

// Fake is a Clock a test owns outright: it never advances on its own, so a
// test can assert "nothing happened yet", move time forward by exactly the
// threshold under test, and assert again. Safe for concurrent use because
// production code (e.g. a retention job goroutine) may read it while a test
// goroutine advances it.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

// NewFake returns a Fake pinned at t. Tests should pass a UTC time; Now does
// not normalise, so a caller that seeds a non-UTC time gets a non-UTC time
// back — mirroring Real would hide that mistake instead of catching it.
func NewFake(t time.Time) *Fake {
	return &Fake{t: t}
}

// Now returns the time Fake was last Set or Advance'd to.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

// Set pins Fake at t, replacing whatever time it held before. Use this to
// jump straight to a scenario (e.g. "5 minutes from now") without caring
// about the path there.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

// Advance moves Fake forward by d. Use this to simulate the passage of time
// between two assertions, e.g. one minute between panel polls.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// Ms converts t to the int64 ms UTC epoch form every stored timestamp in
// mon-server uses (spec §3: "Времена — ms UTC").
func Ms(t time.Time) int64 {
	return t.UnixMilli()
}

// FromMs converts a stored ms UTC epoch value back to a time.Time in UTC, the
// inverse of Ms. Round-tripping a value through Ms/FromMs must be lossless
// down to the millisecond, since that is the precision everything on disk is
// kept at.
func FromMs(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}
