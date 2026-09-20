package state

import (
	"encoding/json"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Thresholds are spec §7.2's knobs in the units the machine reasons in.
// They are read from the settings table on every heartbeat (never cached),
// because an administrator can change them at runtime and the next cycle is
// expected to use the new values.
type Thresholds struct {
	// DownAfter is how many consecutive failures of live cycles make a
	// target DOWN (default 3).
	DownAfter int
	// UpAfter is how many consecutive successes bring a DOWN target back to
	// UP (default 2). A target leaving UNKNOWN does not wait for it: spec
	// §7.2 calls the first success the starting state.
	UpAfter int
	// FlapN is how many UP<->DOWN transitions inside FlapMin make a target
	// FLAPPING (default 4).
	FlapN int
	// FlapMin is the sliding window FlapN transitions are counted over
	// (default 30 min).
	FlapMin time.Duration
	// FlapHoldMin is how long FLAPPING must go without a transition before
	// the target drops back to its actual state (default 15 min).
	FlapHoldMin time.Duration
}

// ThresholdsFrom converts stored settings (spec §9.4) into Thresholds,
// forcing every count to at least 1 and every window to at least a minute.
// A zero or negative threshold — which the settings table can hold, since
// it stores whatever an admin typed — would otherwise make the machine
// degenerate (downAfter 0 means "DOWN before any result"), and refusing to
// run at all would be worse than clamping.
func ThresholdsFrom(set *store.Settings) Thresholds {
	return Thresholds{
		DownAfter:   atLeast(set.DownAfter, 1),
		UpAfter:     atLeast(set.UpAfter, 1),
		FlapN:       atLeast(set.FlapN, 1),
		FlapMin:     time.Duration(atLeast(set.FlapMin, 1)) * time.Minute,
		FlapHoldMin: time.Duration(atLeast(set.FlapHoldMin, 1)) * time.Minute,
	}
}

func atLeast(v, min int) int {
	if v < min {
		return min
	}
	return v
}

// Outcome is one live-cycle probe result reduced to what the machine
// actually decides on: did it work, and if not, what did the mon-client
// blame. Reason is already defaulted to ReasonHTTPError for a failure the
// mon-client left unexplained, so the machine never has to invent one.
type Outcome struct {
	Ok     bool
	Reason string
}

// OutcomeOf reduces a wire Result to an Outcome (protocol §5.3: `reason` is
// nullable, and a null on a failing result still has to produce an event
// with a reason in it).
func OutcomeOf(r Result) Outcome {
	if r.Ok {
		return Outcome{Ok: true}
	}
	reason := ReasonHTTPError
	if r.Reason != nil && *r.Reason != "" {
		reason = *r.Reason
	}
	return Outcome{Reason: reason}
}

// Transition is one state change the machine decided on: what the panel's
// event feed (contract §4.6) and, in PANEL_DOWN, Telegram will carry.
// Silent marks the transitions spec §7.2 says are events only — the
// UP<->DOWN flips inside FLAPPING, which must not each produce their own
// Telegram message; that is the whole point of the FLAPPING state.
type Transition struct {
	From   string
	To     string
	Reason string
	Silent bool
	// SinceMs is when the From state began — Target.Since as it stood
	// before this transition rewrote it. Spec §7.2's "UP" row needs it: the
	// Telegram message for DOWN → UP has to carry how long the target was
	// down, and once the row is saved that start time is gone.
	SinceMs int64
}

// Step is the state machine of spec §7.2 as a pure function: it takes a
// target row, the thresholds, one live-cycle result and mon-server's
// receive time, and returns the row as it should now be plus the
// transitions to publish. Nothing here touches the database, the clock or
// the notifier, which is what lets the whole transition table be tested as
// a plain table (docs/agents/testing.md) and what keeps "when does a target
// go DOWN" readable in one place.
//
// A PAUSED target is returned untouched: its inbound is not in the config
// at all (spec §4 step 3), so a result for it is stale and must not move
// any state.
func Step(cur store.Target, th Thresholds, res Outcome, now time.Time) (store.Target, []Transition) {
	if cur.State == store.TargetPaused {
		return cur, nil
	}

	nowMs := clock.Ms(now)
	next := cur
	var evs []Transition

	// FLAPPING first: a hold that has run out ends before this result is
	// applied, so the result lands in the state the target has actually
	// returned to (spec §7.2: "flapHoldMin без переходов → фактическое
	// состояние").
	if next.State == store.TargetFlapping && next.FlappingUntil != nil && nowMs >= *next.FlappingUntil {
		to := derivedState(cur, th)
		reason := ReasonRecovered
		if to == store.TargetDown {
			reason = lastFailureReason(cur.Reason)
		}
		evs = append(evs, Transition{From: store.TargetFlapping, To: to, Reason: reason, SinceMs: cur.Since})
		next.State = to
		next.Since = nowMs
		next.FlappingUntil = nil
		// The window is cleared with the hold: it has just been served, and
		// keeping the four old transitions would send the target straight
		// back into FLAPPING on the very next flip, which would make the
		// cooldown meaningless.
		next.Transitions = "[]"
		if to == store.TargetUp {
			next.Reason = ""
		} else {
			next.Reason = reason
		}
	}

	next.LastResultAt = &nowMs
	if res.Ok {
		next.ConsecutiveOk++
		next.ConsecutiveFail = 0
	} else {
		next.ConsecutiveFail++
		next.ConsecutiveOk = 0
	}

	if next.State == store.TargetFlapping {
		// Inside FLAPPING the target keeps flipping underneath; the row
		// stays FLAPPING (so the panel shows one unstable target rather
		// than a stream of UP/DOWN) while each flip is still filed as an
		// event, silently, and restarts the hold — the exit condition is
		// "flapHoldMin without transitions".
		from := derivedState(cur, th)
		to := derivedState(next, th)
		if from != to {
			next.Transitions, _ = recordTransition(next.Transitions, nowMs, th.FlapMin)
			until := nowMs + th.FlapHoldMin.Milliseconds()
			next.FlappingUntil = &until
			next.Reason = rowReason(res)
			evs = append(evs, Transition{From: from, To: to, Reason: eventReason(res), Silent: true, SinceMs: next.Since})
		}
		return next, evs
	}

	want := next.State
	switch {
	case res.Ok && next.State == store.TargetUnknown:
		// Spec §7.2: the first success is the starting state, with no
		// upAfter wait — a fresh target that works should not spend a
		// minute claiming to be unknown.
		want = store.TargetUp
	case res.Ok && next.State == store.TargetDown && next.ConsecutiveOk >= th.UpAfter:
		want = store.TargetUp
	case !res.Ok && next.State != store.TargetDown && next.ConsecutiveFail >= th.DownAfter:
		want = store.TargetDown
	}
	if want == next.State {
		return next, evs
	}

	from := next.State
	// The start of the state being left, captured before Since is rewritten:
	// it is what a DOWN → UP transition reports as the downtime (spec §7.2).
	fromSince := next.Since
	if isUpDown(from) && isUpDown(want) {
		var n int
		next.Transitions, n = recordTransition(next.Transitions, nowMs, th.FlapMin)
		if n >= th.FlapN {
			until := nowMs + th.FlapHoldMin.Milliseconds()
			next.State = store.TargetFlapping
			next.Since = nowMs
			next.FlappingUntil = &until
			next.Reason = rowReason(res)
			return next, append(evs, Transition{From: from, To: store.TargetFlapping, Reason: ReasonFlapping, SinceMs: fromSince})
		}
	}

	next.State = want
	next.Since = nowMs
	next.Reason = rowReason(res)
	return next, append(evs, Transition{From: from, To: want, Reason: eventReason(res), SinceMs: fromSince})
}

// derivedState is what a FLAPPING target's counters say it really is — the
// state it would show if FLAPPING were not masking it, needed both for the
// flips filed while flapping and for the state it drops back to on exit.
// It is total: after any result exactly one of the two counters is
// non-zero, and a streak too short to cross its threshold means the target
// is still in the state it was flipping away from.
func derivedState(t store.Target, th Thresholds) string {
	switch {
	case t.ConsecutiveFail >= th.DownAfter:
		return store.TargetDown
	case t.ConsecutiveOk >= th.UpAfter:
		return store.TargetUp
	case t.ConsecutiveFail > 0:
		return store.TargetUp
	case t.ConsecutiveOk > 0:
		return store.TargetDown
	default:
		// No results at all, which a FLAPPING target cannot reach — treat
		// it as UP rather than inventing a failure nobody reported.
		return store.TargetUp
	}
}

// isUpDown reports whether s is one of the two states whose flips feed the
// FLAPPING window (spec §7.2 counts UP<->DOWN transitions; leaving UNKNOWN
// or PAUSED is a config or liveness event, not instability).
func isUpDown(s string) bool { return s == store.TargetUp || s == store.TargetDown }

// eventReason is the reason a result-driven transition publishes: the
// mon-client's own diagnosis for a failure, ReasonRecovered for every
// transition into UP (spec §7.2's "UP" row).
func eventReason(res Outcome) string {
	if res.Ok {
		return ReasonRecovered
	}
	return res.Reason
}

// rowReason is what the target row keeps as its current reason: a failure's
// diagnosis, or nothing at all while the target is working (the admin UI
// and the panel show this field next to the state, where a stale
// "tls_timeout" on a healthy target would be actively misleading).
func rowReason(res Outcome) string {
	if res.Ok {
		return ""
	}
	return res.Reason
}

// lastFailureReason falls back to ReasonHTTPError when a target somehow
// reaches DOWN with no recorded reason (a row written before this code, or
// a failure the mon-client never explained): an event's reason field must
// always carry a dictionary value.
func lastFailureReason(reason string) string {
	if reason == "" {
		return ReasonHTTPError
	}
	return reason
}

// recordTransition appends now to the sliding UP<->DOWN window stored in
// Target.Transitions, dropping everything older than window, and returns
// the new JSON and how many transitions are left inside it — the number
// spec §7.2 compares against flapN. A column that fails to decode (only
// this package writes it) restarts from an empty window rather than
// failing the whole heartbeat.
func recordTransition(raw string, nowMs int64, window time.Duration) (string, int) {
	kept := make([]int64, 0, 8)
	cutoff := nowMs - window.Milliseconds()
	for _, ts := range decodeTransitions(raw) {
		if ts > cutoff {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, nowMs)

	b, err := json.Marshal(kept)
	if err != nil {
		// Marshalling a []int64 cannot fail.
		panic("state: marshal transitions: " + err.Error())
	}
	return string(b), len(kept)
}

// decodeTransitions reads Target.Transitions, treating an empty or corrupt
// value as "no transitions recorded" (see recordTransition).
func decodeTransitions(raw string) []int64 {
	if raw == "" {
		return nil
	}
	var out []int64
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}
