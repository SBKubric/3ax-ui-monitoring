package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// tRef is the fixed instant every retention test measures "old" and "fresh"
// against, via fakeStore's Fake clock.
var tRef = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ms(t time.Time) int64 { return clock.Ms(t) }

func ptr(v int64) *int64 { return &v }

// TestRetention_EventsOutbox checks spec §3's events_outbox rule: only a
// row that is both sent and older than 7 days goes; an unsent row is never
// touched no matter its age (it is the PANEL_DOWN buffer, spec §4.1), and a
// sent-but-fresh row is kept too.
func TestRetention_EventsOutbox(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	old := tRef.Add(-8 * 24 * time.Hour)
	fresh := tRef.Add(-1 * time.Hour)

	rows := []EventOutbox{
		{Id: "old-sent", Ts: ms(old), Payload: "{}", SentAt: ptr(ms(old))},
		{Id: "old-unsent", Ts: ms(old), Payload: "{}", SentAt: nil},
		{Id: "fresh-sent", Ts: ms(fresh), Payload: "{}", SentAt: ptr(ms(fresh))},
	}
	for _, r := range rows {
		if err := s.DB.Create(&r).Error; err != nil {
			t.Fatalf("seed %s: %v", r.Id, err)
		}
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.Events != 1 {
		t.Fatalf("report.Events = %d, want 1", report.Events)
	}

	var remaining []EventOutbox
	if err := s.DB.Order("id").Find(&remaining).Error; err != nil {
		t.Fatalf("find remaining: %v", err)
	}
	var ids []string
	for _, r := range remaining {
		ids = append(ids, r.Id)
	}
	want := []string{"fresh-sent", "old-unsent"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining events_outbox ids = %v, want %v", ids, want)
	}
}

// TestRetention_StatsBuckets mirrors TestRetention_EventsOutbox for
// stats_buckets, which shares the same sent_at rule (spec §3).
func TestRetention_StatsBuckets(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	old := tRef.Add(-8 * 24 * time.Hour)
	fresh := tRef.Add(-1 * time.Hour)

	rows := []StatsBucket{
		{MonClientId: "mc", InboundKind: InboundKindXray, InboundId: 1, Path: PathDirect, BucketStart: 1, SentAt: ptr(ms(old))},
		{MonClientId: "mc", InboundKind: InboundKindXray, InboundId: 2, Path: PathDirect, BucketStart: 2, SentAt: nil},
		{MonClientId: "mc", InboundKind: InboundKindXray, InboundId: 3, Path: PathDirect, BucketStart: 3, SentAt: ptr(ms(fresh))},
	}
	for i := range rows {
		if err := s.DB.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed bucket %d: %v", rows[i].InboundId, err)
		}
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.Stats != 1 {
		t.Fatalf("report.Stats = %d, want 1", report.Stats)
	}

	var count int64
	if err := s.DB.Model(&StatsBucket{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("stats_buckets rows left = %d, want 2 (unsent + fresh kept)", count)
	}
}

// TestRetention_ProbeSeen checks spec §3's 24h probe_seen sweep.
func TestRetention_ProbeSeen(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	old := tRef.Add(-25 * time.Hour)
	fresh := tRef.Add(-1 * time.Hour)

	if err := s.DB.Create(&ProbeSeen{MonClientId: "mc", InboundKind: InboundKindXray, Path: PathDirect, SeenAt: ms(old)}).Error; err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if err := s.DB.Create(&ProbeSeen{MonClientId: "mc", InboundKind: InboundKindXray, Path: PathDirect, SeenAt: ms(fresh)}).Error; err != nil {
		t.Fatalf("seed fresh: %v", err)
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.ProbeSeen != 1 {
		t.Fatalf("report.ProbeSeen = %d, want 1", report.ProbeSeen)
	}
	var count int64
	if err := s.DB.Model(&ProbeSeen{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("probe_seen rows left = %d, want 1 (the fresh one)", count)
	}
}

// TestRetention_RegistrationRequests checks spec §3/§6: a pending request is
// never touched regardless of age; a resolved (non-pending) one ages out
// after 7 days, and a fresh resolved one is kept.
func TestRetention_RegistrationRequests(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	old := tRef.Add(-8 * 24 * time.Hour)
	fresh := tRef.Add(-1 * time.Hour)

	rows := []RegistrationRequest{
		{RequestId: "pending-old", PairingCode: "AAAAAA", Hostname: "h", RemoteIp: "1.1.1.1", Status: RegistrationPending, CreatedAt: ms(old), ExpiresAt: ms(old.Add(5 * time.Minute))},
		{RequestId: "rejected-old", PairingCode: "BBBBBB", Hostname: "h", RemoteIp: "1.1.1.1", Status: RegistrationRejected, CreatedAt: ms(old), ExpiresAt: ms(old.Add(5 * time.Minute))},
		{RequestId: "rejected-fresh", PairingCode: "CCCCCC", Hostname: "h", RemoteIp: "1.1.1.1", Status: RegistrationRejected, CreatedAt: ms(fresh), ExpiresAt: ms(fresh.Add(5 * time.Minute))},
	}
	for i := range rows {
		if err := s.DB.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed %s: %v", rows[i].RequestId, err)
		}
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.Requests != 1 {
		t.Fatalf("report.Requests = %d, want 1", report.Requests)
	}

	var remaining []RegistrationRequest
	if err := s.DB.Order("request_id").Find(&remaining).Error; err != nil {
		t.Fatalf("find remaining: %v", err)
	}
	var ids []string
	for _, r := range remaining {
		ids = append(ids, r.RequestId)
	}
	want := []string{"pending-old", "rejected-fresh"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining registration_requests ids = %v, want %v", ids, want)
	}
}

// TestRetention_AdminSessions checks spec §3: an expired session row is
// swept, a still-live one is left alone (sessions.go's Session already
// refuses an expired one at read time — this is just housekeeping).
func TestRetention_AdminSessions(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	if err := s.DB.Create(&AdminSession{Id: "expired", CreatedAt: ms(tRef.Add(-2 * SessionTTL)), ExpiresAt: ms(tRef.Add(-1 * time.Hour))}).Error; err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	if err := s.DB.Create(&AdminSession{Id: "live", CreatedAt: ms(tRef), ExpiresAt: ms(tRef.Add(SessionTTL))}).Error; err != nil {
		t.Fatalf("seed live: %v", err)
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.Sessions != 1 {
		t.Fatalf("report.Sessions = %d, want 1", report.Sessions)
	}

	var remaining []AdminSession
	if err := s.DB.Find(&remaining).Error; err != nil {
		t.Fatalf("find remaining: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Id != "live" {
		t.Fatalf("remaining admin_sessions = %+v, want only 'live'", remaining)
	}
}

// TestRetention_LoginAttempts checks the login_attempts rule: a lapsed
// lockout (locked_until in the past) is swept; a currently-active lockout
// and a row that has never been locked (mid-count, locked_until = 0) are
// both left alone (sessions.go's RecordLoginFailure/LoginLocked treat "row
// gone" identically to "row present but lapsed", so deleting only lapsed
// rows changes nothing observable — see retention.go's doc comment).
func TestRetention_LoginAttempts(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)

	if err := s.DB.Create(&LoginAttempt{Ip: "lapsed", Failures: 0, LockedUntil: ms(tRef.Add(-time.Hour))}).Error; err != nil {
		t.Fatalf("seed lapsed: %v", err)
	}
	if err := s.DB.Create(&LoginAttempt{Ip: "active-lock", Failures: 0, LockedUntil: ms(tRef.Add(time.Hour))}).Error; err != nil {
		t.Fatalf("seed active-lock: %v", err)
	}
	if err := s.DB.Create(&LoginAttempt{Ip: "mid-count", Failures: 3, LockedUntil: 0}).Error; err != nil {
		t.Fatalf("seed mid-count: %v", err)
	}

	report, err := s.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.LoginAttempts != 1 {
		t.Fatalf("report.LoginAttempts = %d, want 1", report.LoginAttempts)
	}

	var remaining []LoginAttempt
	if err := s.DB.Order("ip").Find(&remaining).Error; err != nil {
		t.Fatalf("find remaining: %v", err)
	}
	var ips []string
	for _, r := range remaining {
		ips = append(ips, r.Ip)
	}
	want := []string{"active-lock", "mid-count"}
	if strings.Join(ips, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining login_attempts ips = %v, want %v", ips, want)
	}
}

// countingLogger wraps gorm's silent logger and counts every SQL statement
// whose text contains substr, so a test can prove the batching loop
// actually issued more than one DELETE instead of a single unbounded one.
type countingLogger struct {
	logger.Interface
	substr string
	n      int
}

func (c *countingLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	if strings.Contains(sql, c.substr) {
		c.n++
	}
	c.Interface.Trace(ctx, begin, fc, err)
}

// TestRetention_BatchBoundary checks the issue's batch-boundary case: 2500
// old, sent events_outbox rows — more than two retentionBatch (1000)
// batches — are all removed, and the deletion actually took at least three
// statements (2500 / 1000 rounds up to 3), proving the loop batches rather
// than issuing one unbounded DELETE against the single write connection
// (architecture brief §3.7 / issue #13: "батчами").
func TestRetention_BatchBoundary(t *testing.T) {
	s, clk := fakeStore(t)
	clk.Set(tRef)
	old := ms(tRef.Add(-8 * 24 * time.Hour))

	const n = 2*retentionBatch + 500
	rows := make([]EventOutbox, n)
	for i := range rows {
		rows[i] = EventOutbox{
			Id:      idFor(i),
			Ts:      old,
			Payload: "{}",
			SentAt:  ptr(old),
		}
	}
	// Insert in chunks: gorm/sqlite has its own bind-variable limit per
	// statement well below 2500 rows at once.
	for i := 0; i < len(rows); i += 500 {
		end := i + 500
		if end > len(rows) {
			end = len(rows)
		}
		if err := s.DB.Create(rows[i:end]).Error; err != nil {
			t.Fatalf("seed batch %d: %v", i, err)
		}
	}

	cl := &countingLogger{Interface: s.DB.Logger, substr: "DELETE FROM events_outbox"}
	withLogger := *s
	withLogger.DB = s.DB.Session(&gorm.Session{Logger: cl})

	report, err := withLogger.Retention(context.Background())
	if err != nil {
		t.Fatalf("Retention: %v", err)
	}
	if report.Events != int64(n) {
		t.Fatalf("report.Events = %d, want %d", report.Events, n)
	}
	if cl.n < 3 {
		t.Fatalf("events_outbox DELETE statements = %d, want >= 3 (batch size %d over %d rows)", cl.n, retentionBatch, n)
	}

	var count int64
	if err := s.DB.Model(&EventOutbox{}).Count(&count).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("events_outbox rows left = %d, want 0", count)
	}
}

func idFor(i int) string {
	return fmt.Sprintf("evt-%d", i)
}
