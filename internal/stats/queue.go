package stats

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Closed returns the buckets that are ready for POST /stats: closed — one
// minute past the end of their window — and not yet accepted by the panel,
// oldest first. limit caps the batch at contract §4.7's 2000; zero or less
// asks for that maximum.
//
// It only reports; nothing is marked here. The dispatcher marks what the panel
// answered 200 to, through MarkSent.
func (r *Recorder) Closed(ctx context.Context, limit int) ([]panel.Stat, error) {
	return r.ClosedFrom(ctx, 0, limit)
}

// ClosedFrom is Closed with the oldest skip ready buckets passed over. The
// dispatcher uses it to step past a batch the panel refused: a 4xx batch keeps
// its sent_at NULL, and without the skip the next read would hand back the
// same rows forever.
func (r *Recorder) ClosedFrom(ctx context.Context, skip, limit int) ([]panel.Stat, error) {
	if limit <= 0 || limit > panel.MaxStats {
		limit = panel.MaxStats
	}
	if skip < 0 {
		skip = 0
	}
	// closed ⇔ now ≥ bucketStart + window + close delay.
	cutoff := r.nowMS() - WindowMS - CloseDelayMS

	var rows []store.StatsBucket
	q := r.st.DB().WithContext(ctx).
		Where("sent_at IS NULL AND bucket_start <= ?", cutoff).
		Order("bucket_start asc, id asc").
		Limit(limit)
	if skip > 0 {
		q = q.Offset(skip)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("stats: read closed buckets: %w", err)
	}

	out := make([]panel.Stat, 0, len(rows))
	for i := range rows {
		out = append(out, statOf(rows[i]))
	}
	return out, nil
}

// MarkSent records that the panel accepted these aggregates, at ms UTC. It is
// only ever called after a 200.
//
// A bucket that changed while it was in flight — a cycle resent in the
// meantime — is left alone: its counts no longer match what the panel was
// given, so it stays unsent and goes out again with the corrected figures.
func (r *Recorder) MarkSent(ctx context.Context, sent []panel.Stat, at int64) error {
	if len(sent) == 0 {
		return nil
	}
	err := r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, s := range sent {
			res := tx.Model(&store.StatsBucket{}).
				Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ? AND bucket_start = ?",
					s.MonClientID, s.InboundKind, s.InboundID, s.Path, s.BucketStart).
				Where("n_ok = ? AND n_fail = ?", s.NOk, s.NFail).
				Update("sent_at", at)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				r.log.Debug("bucket changed while it was being delivered, leaving it queued",
					"monClientId", s.MonClientID, "inboundKind", s.InboundKind,
					"inboundId", s.InboundID, "path", s.Path, "bucketStart", s.BucketStart)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("stats: mark buckets sent: %w", err)
	}
	return nil
}

// statOf renders a row as the wire shape of contract §4.7. The latency fields
// are copied, never shared with the row, and are all NULL when nothing
// succeeded.
func statOf(row store.StatsBucket) panel.Stat {
	out := panel.Stat{
		MonClientID: row.MonClientID,
		InboundKind: row.InboundKind,
		InboundID:   row.InboundID,
		Path:        row.Path,
		BucketStart: row.BucketStart,
		NOk:         row.NOk,
		NFail:       row.NFail,
	}
	if row.NOk > 0 {
		if row.LatMin != nil {
			out.LatencyMinMS = ptr(*row.LatMin)
		}
		if row.LatAvg != nil {
			out.LatencyAvgMS = ptr(*row.LatAvg)
		}
		if row.LatMax != nil {
			out.LatencyMaxMS = ptr(*row.LatMax)
		}
	}
	if row.HandshakeMs != nil && row.InboundKind == store.InboundKindAWG {
		out.HandshakeMS = ptr(*row.HandshakeMs)
	}
	return out
}
