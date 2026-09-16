package stats

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Record folds one accepted cycle into its buckets (spec §7.4). It implements
// state.StatsSink.
//
// cycleTS is the bucketing timestamp of §7.1 step 1, already clamped to
// mon-server's receive time, and it alone decides which window the results
// belong to: a cycle that arrives long after its window folds into that
// window all the same, and clears the bucket's sent_at so the next dispatch
// delivers the corrected aggregate.
//
// unverified marks a cycle whose heartbeat was never acknowledged. Its
// failures are dropped — they are a gap in the record, not evidence about the
// target — while its successes count in full, latencies included.
//
// The whole cycle is one transaction: a heartbeat either updates every bucket
// it touches or none of them.
func (r *Recorder) Record(ctx context.Context, monClientID string, cycleTS int64, results []state.Result, unverified bool) error {
	if monClientID == "" || len(results) == 0 {
		return nil
	}
	deltas := group(monClientID, cycleTS, results, unverified)
	if len(deltas) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowMS()
	r.pruneLocked(now)

	// The accumulators are only updated once the rows are durable, so a
	// failed transaction cannot leave the in-memory sums ahead of the table.
	folds := make(map[bucketKey]fold, len(deltas))
	err := r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, d := range deltas {
			f, err := r.applyLocked(tx, d, cycleTS)
			if err != nil {
				return err
			}
			folds[d.key] = f
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("stats: record cycle of %q at %d: %w", monClientID, cycleTS, err)
	}
	for key, f := range folds {
		r.acc[key] = &fold{sum: f.sum, n: f.n, handshakeTS: f.handshakeTS}
	}
	return nil
}

// delta is everything one cycle has to say about one bucket.
type delta struct {
	key   bucketKey
	nOk   int
	nFail int
	// samples are the tlsMs of the successful probes that reported one. A
	// success without a tlsMs counts towards n_ok and towards no latency.
	samples []int64
	// handshake is the handshakeMs of the last successful AWG probe of the
	// cycle, nil for every other kind and for a cycle that did not succeed.
	handshake *int64
}

// group turns the results of one cycle into one delta per target, dropping
// what the bucket must not see: the failures of an unverified cycle.
func group(monClientID string, cycleTS int64, results []state.Result, unverified bool) []delta {
	bucketStart := Start(cycleTS)
	index := make(map[bucketKey]int, len(results))
	out := make([]delta, 0, len(results))

	for _, res := range results {
		if unverified && !res.OK {
			// A gap, not a failure: the probe's destination is mon-server
			// itself, so its own unreachability looks exactly like a broken
			// tunnel (spec §7.4).
			continue
		}
		key := bucketKey{
			monClientID: monClientID,
			inboundKind: res.InboundKind,
			inboundID:   res.InboundID,
			path:        res.Path,
			bucketStart: bucketStart,
		}
		at, ok := index[key]
		if !ok {
			at = len(out)
			index[key] = at
			out = append(out, delta{key: key})
		}
		d := &out[at]
		if !res.OK {
			d.nFail++
			continue
		}
		d.nOk++
		if res.TLSMS != nil {
			d.samples = append(d.samples, *res.TLSMS)
		}
		// handshake_ms is AmneziaWG only (spec §7.4): an xray bucket leaves
		// the column NULL however much the mon-client reports.
		if res.InboundKind == store.InboundKindAWG && res.HandshakeMS != nil {
			d.handshake = ptr(*res.HandshakeMS)
		}
	}
	return out
}

// applyLocked folds one delta into its row inside the caller's transaction and
// returns the accumulator the row's average was computed from. The caller
// holds r.mu.
func (r *Recorder) applyLocked(tx *gorm.DB, d delta, cycleTS int64) (fold, error) {
	row, found, err := loadBucket(tx, d.key)
	if err != nil {
		return fold{}, err
	}
	f := r.accumulatorLocked(d.key, row)

	row.NOk += d.nOk
	row.NFail += d.nFail

	for _, ms := range d.samples {
		if row.LatMin == nil || ms < *row.LatMin {
			row.LatMin = ptr(ms)
		}
		if row.LatMax == nil || ms > *row.LatMax {
			row.LatMax = ptr(ms)
		}
		f.sum += ms
		f.n++
	}
	if f.n > 0 {
		row.LatAvg = ptr(divRound(f.sum, f.n))
	}
	// The last successful cycle of the bucket owns handshake_ms, so a cycle
	// that arrives late does not overwrite a newer one. A reseeded bucket has
	// no idea when its value came from and lets the new one through.
	if d.handshake != nil && cycleTS >= f.handshakeTS {
		row.HandshakeMs = ptr(*d.handshake)
		f.handshakeTS = cycleTS
	}
	if row.NOk == 0 {
		// Nothing succeeded, so there is nothing to report: contract §4.7
		// wants NULL here, never zero.
		row.LatMin, row.LatAvg, row.LatMax = nil, nil, nil
	}
	if found && row.SentAt != nil {
		// A resent cycle changed a bucket the panel already has. Clearing
		// sent_at is how the corrected aggregate reaches it: the panel
		// upserts on the bucket key, so the repeat replaces the old figure
		// (spec §7.4).
		row.SentAt = nil
		r.log.Debug("a late cycle changed a delivered bucket, it will be sent again",
			"monClientId", d.key.monClientID, "inboundKind", d.key.inboundKind,
			"inboundId", d.key.inboundID, "path", d.key.path, "bucketStart", d.key.bucketStart)
	}

	if found {
		if err := tx.Save(&row).Error; err != nil {
			return fold{}, fmt.Errorf("save bucket: %w", err)
		}
		return f, nil
	}
	if err := tx.Create(&row).Error; err != nil {
		return fold{}, fmt.Errorf("create bucket: %w", err)
	}
	return f, nil
}

// loadBucket reads the bucket row of a key, or returns the empty row that has
// yet to be created.
func loadBucket(tx *gorm.DB, key bucketKey) (store.StatsBucket, bool, error) {
	var row store.StatsBucket
	err := tx.Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ? AND bucket_start = ?",
		key.monClientID, key.inboundKind, key.inboundID, key.path, key.bucketStart).
		Take(&row).Error
	switch {
	case err == nil:
		return row, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.StatsBucket{
			MonClientID: key.monClientID,
			InboundKind: key.inboundKind,
			InboundID:   key.inboundID,
			Path:        key.path,
			BucketStart: key.bucketStart,
		}, false, nil
	default:
		return store.StatsBucket{}, false, fmt.Errorf("read bucket: %w", err)
	}
}

// accumulatorLocked returns the exact sum behind a bucket, reseeding it from
// the stored row when this process has never folded into that bucket — after a
// restart, or once the cache has aged the entry out. The seed assumes the
// stored average covers every success, which is true unless a mon-client
// reported a success with no tlsMs; from the next sample on the sum is exact
// again either way. The copy is deliberate: the cache is only updated once the
// transaction that produced the new figures has committed.
func (r *Recorder) accumulatorLocked(key bucketKey, row store.StatsBucket) fold {
	if f, ok := r.acc[key]; ok {
		return *f
	}
	var f fold
	if row.LatAvg != nil && row.NOk > 0 {
		f.n = int64(row.NOk)
		f.sum = *row.LatAvg * f.n
	}
	return f
}
