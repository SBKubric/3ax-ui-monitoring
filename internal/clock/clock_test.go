package clock

import (
	"testing"
	"time"
)

// TestFake_SetAdvance checks that Fake only ever reports a time it was
// explicitly told to hold, and that Set replaces it outright while Advance
// adds a delta — the two ways a test drives simulated time forward.
func TestFake_SetAdvance(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := NewFake(start)

	if got := f.Now(); !got.Equal(start) {
		t.Fatalf("Now() = %v, want %v", got, start)
	}

	next := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	f.Set(next)
	if got := f.Now(); !got.Equal(next) {
		t.Fatalf("after Set: Now() = %v, want %v", got, next)
	}

	f.Advance(90 * time.Second)
	want := next.Add(90 * time.Second)
	if got := f.Now(); !got.Equal(want) {
		t.Fatalf("after Advance: Now() = %v, want %v", got, want)
	}
}

// TestMsFromMs_RoundTrip checks that converting a time to the stored ms
// epoch form and back loses nothing down to the millisecond, since every
// timestamp on disk goes through this pair (spec §3: "Времена — ms UTC").
func TestMsFromMs_RoundTrip(t *testing.T) {
	cases := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1999, 12, 31, 23, 59, 59, 999_000_000, time.UTC),
		time.UnixMilli(0).UTC(),
	}
	for _, want := range cases {
		ms := Ms(want)
		got := FromMs(ms)
		if !got.Equal(want) {
			t.Fatalf("FromMs(Ms(%v)) = %v, want %v", want, got, want)
		}
	}
}

// TestMs_KnownValue pins Ms to a known epoch value so a future refactor that
// changes units (e.g. to microseconds) fails loudly instead of only breaking
// round-trip symmetry.
func TestMs_KnownValue(t *testing.T) {
	got := Ms(time.Date(1970, 1, 1, 0, 0, 1, 0, time.UTC))
	if got != 1000 {
		t.Fatalf("Ms = %d, want 1000", got)
	}
}

// TestReal_ReturnsUTC checks that Real never leaks a non-UTC location, since
// mon-server treats every timestamp as ms UTC epoch.
func TestReal_ReturnsUTC(t *testing.T) {
	got := (Real{}).Now()
	if got.Location() != time.UTC {
		t.Fatalf("Real.Now() location = %v, want UTC", got.Location())
	}
}
