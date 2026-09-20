package xray

import (
	"fmt"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// TestRingEvictsOldest pins the window of spec §5: the 501st line pushes the
// first one out and Snapshot still reads oldest first.
func TestRingEvictsOldest(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 9, 12, 15, 0, 0, 0, time.UTC))
	r := NewRingWithClock(RingLines, clk)

	for i := 1; i <= RingLines+1; i++ {
		clk.Advance(time.Millisecond)
		r.AppendText(fmt.Sprintf("line %d", i))
	}

	got := r.Snapshot()
	if len(got) != RingLines {
		t.Fatalf("snapshot has %d lines, want %d", len(got), RingLines)
	}
	if got[0].Text != "line 2" {
		t.Errorf("oldest line = %q, want %q", got[0].Text, "line 2")
	}
	if got[len(got)-1].Text != fmt.Sprintf("line %d", RingLines+1) {
		t.Errorf("newest line = %q, want %q", got[len(got)-1].Text, fmt.Sprintf("line %d", RingLines+1))
	}
	if want := clk.Now(); !got[len(got)-1].At.Equal(want) {
		t.Errorf("newest At = %v, want %v (injected clock)", got[len(got)-1].At, want)
	}
}

// TestRingPartialSnapshot covers the not-yet-wrapped case: a snapshot must
// not hand out the zero values of the unwritten slots.
func TestRingPartialSnapshot(t *testing.T) {
	r := NewRingWithClock(4, clock.NewFake(time.Unix(0, 0).UTC()))
	r.Append(Line{Text: "a"})
	r.Append(Line{Text: "b"})
	got := r.Snapshot()
	if len(got) != 2 || got[0].Text != "a" || got[1].Text != "b" {
		t.Fatalf("snapshot = %+v, want [a b]", got)
	}
}
