// Package stats keeps the five-minute statistics buckets of spec
// mon-server.md §7.4: what the probe results of every accepted cycle add up
// to, per target and per five minutes, and which of those aggregates are ripe
// for POST /stats (§4 step 4).
//
// The package is the state.StatsSink the state machine hands every accepted
// cycle to. The cycle's own timestamp — already clamped to mon-server's
// receive time by §7.1 — decides the bucket, so a cycle the mon-client
// buffered for an hour still folds into the window it happened in, and a
// bucket the panel already has is unmarked so the next dispatch sends the
// corrected figure. The panel upserts on the bucket key, which is what makes
// that repeat safe.
//
// Three rules deserve their names here.
//
// A failure from an unverified cycle is a gap, not evidence. The tunnel probe
// aims at mon-server itself, so mon-server being unreachable cannot be told
// apart from a broken tunnel; the failures of a cycle whose heartbeat was
// never acknowledged are dropped and only its successes count (§7.1,
// mon-protocol.md §5.3). The state machine already filters them, and this
// package filters them again: the rule belongs to the bucket, not to the
// caller.
//
// An average cannot be folded out of an average. lat_avg is a single integer
// millisecond column, and (stored average × count + sample) / (count + 1)
// drifts a little with every rounding, which is exactly what a late cycle
// arriving into a long-closed bucket would do. The recorder therefore keeps
// the exact sum of the samples behind each bucket it has touched in memory and
// writes only the rounded average to the row. A bucket this process has no
// memory of — one folded into after a restart — is reseeded from
// lat_avg × n_ok, which is the most the schema of §3 can say; from there on
// the folding is exact again.
//
// Nothing here talks to the panel. Closed says which buckets are ready and
// MarkSent records the ones it accepted; internal/dispatch does the sending,
// so a bucket is never marked delivered on anything but a 200.
package stats

import (
	"log/slog"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Bucket geometry of spec §7.4.
const (
	// WindowMS is the width of one bucket: five minutes. bucketStart is
	// always a multiple of it, which is what contract §4.7 requires.
	WindowMS int64 = 5 * 60 * 1000
	// CloseDelayMS is how long after the end of its window a bucket stays
	// open, so that a cycle whose heartbeat is a little late still lands in
	// it before it goes out.
	CloseDelayMS int64 = 60 * 1000
)

// accumulatorTTL is how long the exact sum behind a bucket is kept in memory
// after the window ended. It only has to outlive the resends a mon-client can
// still make, which the outbox caps at twenty-four hours (spec §4.1); an entry
// older than that is dropped and the bucket is reseeded from its row if a
// result for it ever turns up again.
const accumulatorTTL int64 = 24 * 60 * 60 * 1000

// Start is the bucket a timestamp falls into: ts − ts % 300000. A timestamp
// exactly on a boundary opens the later window, because a bucket covers
// [start, start+WindowMS).
func Start(ts int64) int64 {
	rem := ts % WindowMS
	if rem < 0 {
		// Only reachable for a timestamp before the epoch, which no clock
		// mon-server trusts produces; floor anyway so the result stays a
		// multiple of the window.
		rem += WindowMS
	}
	return ts - rem
}

// End is the first millisecond after a bucket's window.
func End(bucketStart int64) int64 { return bucketStart + WindowMS }

// ClosesAt is when a bucket becomes eligible for POST /stats: one minute after
// the end of its window (spec §7.4).
func ClosesAt(bucketStart int64) int64 { return End(bucketStart) + CloseDelayMS }

// IsClosed reports whether the bucket starting at bucketStart is closed at
// now. Only closed buckets are sent; an open one is still collecting.
func IsClosed(bucketStart, now int64) bool { return now >= ClosesAt(bucketStart) }

// Recorder folds probe results into stats_buckets and hands the closed ones
// out for delivery. One instance serves every mon-client; its methods
// serialise on a mutex, because folding a cycle is a read-modify-write over a
// bucket row and over the exact sum that row cannot hold.
//
// It is the state.StatsSink of spec §7.1 step 4: state.WithStatsSink wires it
// into the state machine, which calls Record while holding its own lock, so
// nothing here may call back into it.
type Recorder struct {
	st  *store.Store
	clk clock.Clock
	log *slog.Logger

	mu sync.Mutex
	// acc holds what a bucket row cannot express: the exact sum of the
	// latency samples behind lat_avg and the cycle that supplied
	// handshake_ms. It is a cache, never the source of truth: every figure
	// the panel sees comes from the row.
	acc map[bucketKey]*fold
}

// New returns a Recorder. A nil clock means clock.System and a nil logger
// discards; the store is required.
func New(st *store.Store, clk clock.Clock, log *slog.Logger) *Recorder {
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Recorder{st: st, clk: clk, log: log, acc: map[bucketKey]*fold{}}
}

// nowMS is the recorder's own time, the one closing and delivery are judged
// against. A cycle's timestamp is never used for either.
func (r *Recorder) nowMS() int64 { return clock.MS(r.clk.Now()) }

// bucketKey is the identity of one bucket, the key contract §4.7 upserts on.
type bucketKey struct {
	monClientID string
	inboundKind string
	inboundID   int64
	path        string
	bucketStart int64
}

// fold is the part of a bucket the schema of §3 has no column for.
type fold struct {
	// sum and n are the exact sum and count of the latency samples lat_avg
	// is the rounded average of. n is not n_ok: a successful probe without a
	// tlsMs contributes to n_ok and to nothing else.
	sum int64
	n   int64
	// handshakeTS is the timestamp of the cycle handshake_ms came from, so a
	// cycle that arrives late cannot pass itself off as the last successful
	// one. Zero means unknown, which is how a reseeded bucket starts: the
	// next successful cycle then wins by default.
	handshakeTS int64
}

// pruneLocked drops the accumulators of buckets too old to receive anything
// more, so that the cache cannot grow for as long as mon-server runs.
func (r *Recorder) pruneLocked(now int64) {
	cutoff := now - accumulatorTTL
	for key := range r.acc {
		if key.bucketStart < cutoff {
			delete(r.acc, key)
		}
	}
}

// divRound divides sum by n, rounding halves away from zero. Latencies are
// positive, so this is the ordinary round-half-up.
func divRound(sum, n int64) int64 {
	if n == 0 {
		return 0
	}
	if sum >= 0 {
		return (sum + n/2) / n
	}
	return -((-sum + n/2) / n)
}

// ptr copies v onto the heap. Every nullable column is written through it, so
// that no two rows can end up sharing one pointer.
func ptr(v int64) *int64 { return &v }
