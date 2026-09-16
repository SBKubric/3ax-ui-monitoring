// Package clock provides the time source used across mon-server so that
// state machine thresholds, TTLs and retention can be driven deterministically
// in tests.
package clock

import (
	"sync"
	"time"
)

// Clock reports the current time. Production code uses System; tests use Fake.
type Clock interface {
	Now() time.Time
}

// Func adapts a plain function to Clock.
type Func func() time.Time

// Now implements Clock.
func (f Func) Now() time.Time { return f() }

// System is the real wall clock, in UTC.
type System struct{}

// Now implements Clock.
func (System) Now() time.Time { return time.Now().UTC() }

// Fake is a manually advanced clock for tests. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake positioned at t (normalised to UTC).
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

// Now implements Clock.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the clock forward by d.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the clock to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}

// MS returns t as milliseconds since the Unix epoch, the storage and wire form
// used everywhere in mon-server.
func MS(t time.Time) int64 { return t.UnixMilli() }

// FromMS converts milliseconds since the Unix epoch back to a UTC time.
func FromMS(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
