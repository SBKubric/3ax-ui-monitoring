package store

import (
	"context"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Retention windows (spec §3: "Ретеншн (job раз в час)"). Each is how long a
// row is kept *after* it becomes eligible at all (a sent events_outbox row,
// a closed stats_buckets row, a probe_seen arrival, a resolved registration
// request) — an unsent or still-pending row is never touched no matter how
// old, because "sent"/"resolved" is exactly what unlocks these clocks.
const (
	// retentionSent is how long a sent events_outbox or stats_buckets row
	// survives (spec §3: "с sent_at старше 7 дней"), matching the PANEL_DOWN
	// buffer's own "no limit while unsent" rule (spec §4.1): only rows the
	// panel has already confirmed age out here.
	retentionSent = 7 * 24 * time.Hour

	// retentionProbeSeen is how long a tunnel-probe diagnostic row survives
	// (spec §3: "probe_seen старше 24 ч"). It is a log for "is this tunnel
	// reaching mon-server at all", not state, so a day of history is plenty.
	retentionProbeSeen = 24 * time.Hour

	// retentionRequests is how long a resolved (non-pending) registration
	// request survives (spec §3: "registration_requests не-pending старше 7
	// дней"). Pending requests are never in scope: they expire into
	// "expired" well before 7 days (spec §6's 5-minute TTL) and only then
	// become eligible.
	retentionRequests = 7 * 24 * time.Hour

	// retentionBatch bounds how many rows one DELETE statement removes
	// (architecture brief §3.7 / issue #13: "батчами, без VACUUM"). mon-server
	// keeps exactly one write connection (spec §3), so a single unbounded
	// DELETE against a huge backlog would hold it — and every other write in
	// the process — for as long as that statement runs; looping in batches
	// this small keeps each individual DELETE fast enough that the
	// retention job never starves a heartbeat or poll cycle waiting on the
	// connection.
	retentionBatch = 1000
)

// RetentionReport counts how many rows the hourly retention job (spec §3)
// removed from each table, so app.go's job can log something meaningful only
// when there was actually something to clean up.
type RetentionReport struct {
	Events        int64
	Stats         int64
	ProbeSeen     int64
	Requests      int64
	Sessions      int64
	LoginAttempts int64
}

// Total is the sum of every count in the report, the one number app.go's job
// checks to decide whether logging the report is worth a line at all.
func (r RetentionReport) Total() int64 {
	return r.Events + r.Stats + r.ProbeSeen + r.Requests + r.Sessions + r.LoginAttempts
}

// Retention runs the hourly cleanup job (spec §3, issue #13): every table
// that accumulates rows mon-server no longer needs is pruned in small
// batches, never with VACUUM (that would need to rewrite the whole file,
// which the single write connection cannot afford to block on). Every rule
// only ever deletes rows that are both old *and* no longer live state:
//
//   - events_outbox / stats_buckets: sent_at IS NOT NULL and older than
//     retentionSent. A NULL sent_at means the panel has not confirmed the
//     row yet — that is exactly the PANEL_DOWN buffer (spec §4.1), which has
//     no age limit of its own, so it is never touched here regardless of ts.
//   - probe_seen: seen_at older than retentionProbeSeen.
//   - registration_requests: status != pending and created_at older than
//     retentionRequests. A still-pending request is always kept; it either
//     resolves (approved/rejected) or expires well within the window
//     (spec §6) before it can ever become eligible.
//   - admin_sessions: expires_at in the past. Session.go already refuses an
//     expired session at read time (spec §9.1), so deleting it here is pure
//     housekeeping, never a behaviour change.
//   - login_attempts: a *lapsed* lockout (locked_until != 0 and in the
//     past). A row with locked_until = 0 (never locked, mid-count) is left
//     alone — deleting it would reset an in-progress failure count, which
//     is not what retention is for. A lapsed lockout is safe to delete: with
//     the row gone, LoginLocked reports "not locked" (same as a lapsed
//     lockout still on file) and the next RecordLoginFailure starts a fresh
//     row at Failures=1 (identical to what upserting into the existing,
//     already-reset-to-zero row would have produced) — see sessions.go's
//     RecordLoginFailure, which always zeroes Failures the moment it sets
//     LockedUntil, and LoginLocked, which already treats "not found" and
//     "found but lapsed" as the same answer.
//
// Every cutoff is computed from Clock, never time.Now(), so a test can
// drive this deterministically (architecture brief §1: "time ... read only
// through clock.Clock").
func (s *Store) Retention(ctx context.Context) (RetentionReport, error) {
	now := clock.Ms(s.Clock.Now())

	var report RetentionReport
	var err error

	sentCutoff := now - retentionSent.Milliseconds()
	if report.Events, err = s.deleteBatched(ctx, "events_outbox",
		"sent_at IS NOT NULL AND sent_at < ?", sentCutoff); err != nil {
		return report, err
	}
	if report.Stats, err = s.deleteBatched(ctx, "stats_buckets",
		"sent_at IS NOT NULL AND sent_at < ?", sentCutoff); err != nil {
		return report, err
	}

	probeSeenCutoff := now - retentionProbeSeen.Milliseconds()
	if report.ProbeSeen, err = s.deleteBatched(ctx, "probe_seen",
		"seen_at < ?", probeSeenCutoff); err != nil {
		return report, err
	}

	requestsCutoff := now - retentionRequests.Milliseconds()
	if report.Requests, err = s.deleteBatchedBy(ctx, "registration_requests", "request_id",
		"status != ? AND created_at < ?", RegistrationPending, requestsCutoff); err != nil {
		return report, err
	}

	if report.Sessions, err = s.deleteBatched(ctx, "admin_sessions",
		"expires_at < ?", now); err != nil {
		return report, err
	}

	if report.LoginAttempts, err = s.deleteBatchedBy(ctx, "login_attempts", "ip",
		"locked_until != 0 AND locked_until < ?", now); err != nil {
		return report, err
	}

	return report, nil
}

// deleteBatched removes rows matching where/args from table, retentionBatch
// at a time, by primary key "id" — events_outbox, stats_buckets, probe_seen
// and admin_sessions are all keyed that way. It loops
// `DELETE ... WHERE id IN (SELECT id ... LIMIT retentionBatch)` until a
// round deletes nothing, so a single call never holds the write connection
// for longer than one small batch at a time (issue #13: "батчами").
func (s *Store) deleteBatched(ctx context.Context, table, where string, args ...any) (int64, error) {
	return s.deleteBatchedBy(ctx, table, "id", where, args...)
}

// deleteBatchedBy is deleteBatched parameterised over the primary key
// column, for the two tables not keyed by a plain "id": registration_requests
// (keyed by "request_id") and login_attempts (keyed by "ip").
func (s *Store) deleteBatchedBy(ctx context.Context, table, keyCol, where string, args ...any) (int64, error) {
	var total int64
	for {
		tx := s.DB.WithContext(ctx).Exec(
			"DELETE FROM "+table+" WHERE "+keyCol+" IN (SELECT "+keyCol+" FROM "+table+" WHERE "+where+" LIMIT ?)",
			append(append([]any{}, args...), retentionBatch)...,
		)
		if tx.Error != nil {
			return total, tx.Error
		}
		total += tx.RowsAffected
		if tx.RowsAffected == 0 {
			return total, nil
		}
	}
}
