package store

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// testTime is the instant the fake clock of the tests starts at.
var testTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// openTestStore opens a store on a fresh file driven by a fake clock, and
// closes it when the test ends.
func openTestStore(t *testing.T) (*Store, *clock.Fake) {
	t.Helper()
	fake := clock.NewFake(testTime)
	s, err := Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, WithClock(fake))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s, fake
}

// schemaObjects lists every table and index of the database as
// "<type> <name>" plus its DDL, so two schemas can be compared literally.
func schemaObjects(t *testing.T, s *Store) []string {
	t.Helper()
	var rows []struct {
		Type string
		Name string
		SQL  string
	}
	err := s.DB().Raw("SELECT type, name, COALESCE(sql,'') AS sql FROM sqlite_master ORDER BY type, name").Scan(&rows).Error
	if err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Type+" "+r.Name+" "+r.SQL)
	}
	return out
}

// namesOf returns the sorted names of the sqlite_master rows of one type,
// skipping SQLite's own implicit objects.
func namesOf(t *testing.T, s *Store, kind string) []string {
	t.Helper()
	var names []string
	err := s.DB().Raw("SELECT name FROM sqlite_master WHERE type = ? ORDER BY name", kind).Scan(&names).Error
	if err != nil {
		t.Fatalf("read sqlite_master: %v", err)
	}
	out := names[:0]
	for _, n := range names {
		if strings.HasPrefix(n, "sqlite_") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func TestOpenMigratesEveryTable(t *testing.T) {
	s, _ := openTestStore(t)

	want := []string{
		"admin",
		"admin_sessions",
		"client_configs",
		"events_outbox",
		"login_attempts",
		"mon_clients",
		"panel_inbounds",
		"probe_seen",
		"registration_requests",
		"settings",
		"stats_buckets",
		"targets",
	}
	if got := namesOf(t, s, "table"); !reflect.DeepEqual(got, want) {
		t.Errorf("migrated tables:\n got %v\nwant %v", got, want)
	}
	if len(Models()) != len(want) {
		t.Errorf("Models() has %d entries, the schema has %d tables", len(Models()), len(want))
	}
}

func TestOpenMigratesEveryIndex(t *testing.T) {
	s, _ := openTestStore(t)

	want := []string{
		"idx_ms_admin_sessions_expires_at",
		"idx_ms_events_outbox_sent_at",
		"idx_ms_events_outbox_ts",
		"idx_ms_login_attempts_locked_until",
		"idx_ms_mon_clients_state",
		"idx_ms_mon_clients_token_hash",
		"idx_ms_probe_seen_mon_client",
		"idx_ms_probe_seen_seen_at",
		"idx_ms_registration_requests_expires_at",
		"idx_ms_registration_requests_remote_ip",
		"idx_ms_registration_requests_status",
		"idx_ms_stats_buckets_identity",
		"idx_ms_stats_buckets_sent_at",
		"idx_ms_targets_identity",
		"idx_ms_targets_mon_client",
		"idx_ms_targets_state",
	}
	got := namesOf(t, s, "index")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("migrated indexes:\n got %v\nwant %v", got, want)
	}
	for _, name := range got {
		if !strings.HasPrefix(name, "idx_ms_") {
			t.Errorf("index %q does not use the idx_ms_ prefix", name)
		}
	}
}

func TestOpenTwiceIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mon-server.db")
	fake := clock.NewFake(testTime)

	first, err := Open(path, nil, WithClock(fake))
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := first.SetSetting(KeyPanelURL, "https://panel.example.net/app"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	before := schemaObjects(t, first)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(path, nil, WithClock(fake))
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()

	if after := schemaObjects(t, second); !reflect.DeepEqual(before, after) {
		t.Errorf("reopening changed the schema:\nbefore %v\nafter  %v", before, after)
	}
	got, err := second.Setting(KeyPanelURL)
	if err != nil {
		t.Fatalf("Setting: %v", err)
	}
	if want := "https://panel.example.net/app"; got != want {
		t.Errorf("setting after reopen = %q, want %q", got, want)
	}
}

func TestOpenAppliesPragmas(t *testing.T) {
	s, _ := openTestStore(t)

	var foreignKeys int
	if err := s.DB().Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var busyTimeout int
	if err := s.DB().Raw("PRAGMA busy_timeout").Scan(&busyTimeout).Error; err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if want := int(BusyTimeout.Milliseconds()); busyTimeout != want {
		t.Errorf("busy_timeout = %d, want %d", busyTimeout, want)
	}

	sqlDB, err := s.DB().DB()
	if err != nil {
		t.Fatalf("database handle: %v", err)
	}
	if got := sqlDB.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("max open connections = %d, want 1 (single writer)", got)
	}
}

func TestOpenCreatesTheDataDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "data", "mon-server.db")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("database mode = %04o, want 0600", mode)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open("", nil); err == nil {
		t.Fatal("Open(\"\") succeeded, want an error")
	}
}

func TestStoreClockDrivesNow(t *testing.T) {
	s, fake := openTestStore(t)

	if got, want := s.NowMS(), clock.MS(testTime); got != want {
		t.Errorf("NowMS = %d, want %d", got, want)
	}
	fake.Advance(90 * time.Second)
	if got, want := s.NowMS(), clock.MS(testTime.Add(90*time.Second)); got != want {
		t.Errorf("NowMS after Advance = %d, want %d", got, want)
	}
	if s.Clock() != clock.Clock(fake) {
		t.Error("Clock() did not return the injected clock")
	}
}

func TestUniqueIdentityIndexes(t *testing.T) {
	s, _ := openTestStore(t)

	tests := []struct {
		name string
		rows []any
	}{
		{
			name: "targets",
			rows: []any{
				&Target{MonClientID: "ams-1", InboundKind: InboundKindXray, InboundID: 12, Path: PathProxy, State: TargetUnknown},
				&Target{MonClientID: "ams-1", InboundKind: InboundKindXray, InboundID: 12, Path: PathProxy, State: TargetUp},
			},
		},
		{
			name: "stats_buckets",
			rows: []any{
				&StatsBucket{MonClientID: "ams-1", InboundKind: InboundKindAWG, InboundID: 0, Path: PathDirect, BucketStart: 1757721300000},
				&StatsBucket{MonClientID: "ams-1", InboundKind: InboundKindAWG, InboundID: 0, Path: PathDirect, BucketStart: 1757721300000},
			},
		},
		{
			name: "panel_inbounds",
			rows: []any{
				&PanelInbound{InboundKind: InboundKindXray, InboundID: 12, Port: 443},
				&PanelInbound{InboundKind: InboundKindXray, InboundID: 12, Port: 8443},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.DB().Create(tc.rows[0]).Error; err != nil {
				t.Fatalf("first insert: %v", err)
			}
			if err := s.DB().Create(tc.rows[1]).Error; err == nil {
				t.Fatal("duplicate insert succeeded, want a unique constraint violation")
			}
		})
	}
}

func TestEncodeDecodePaths(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "both paths", raw: `["proxy","direct"]`, want: []string{PathProxy, PathDirect}},
		{name: "direct only", raw: `["direct"]`, want: []string{PathDirect}},
		{name: "empty array", raw: `[]`, want: []string{}},
		{name: "blank column falls back to the default", raw: "", want: DefaultPaths()},
		{name: "broken json", raw: `["proxy"`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodePaths(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("DecodePaths(%q) = %v, want an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodePaths(%q): %v", tc.raw, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DecodePaths(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}

	encoded, err := EncodePaths(DefaultPaths())
	if err != nil {
		t.Fatalf("EncodePaths: %v", err)
	}
	if want := `["proxy","direct"]`; encoded != want {
		t.Errorf("EncodePaths = %q, want %q", encoded, want)
	}
	roundTrip, err := DecodePaths(encoded)
	if err != nil {
		t.Fatalf("DecodePaths: %v", err)
	}
	if !reflect.DeepEqual(roundTrip, DefaultPaths()) {
		t.Errorf("round trip = %v, want %v", roundTrip, DefaultPaths())
	}
	if nilPaths, err := EncodePaths(nil); err != nil || nilPaths != "[]" {
		t.Errorf("EncodePaths(nil) = %q, %v, want \"[]\", nil", nilPaths, err)
	}
}

func TestHashToken(t *testing.T) {
	// The hex SHA-256 of "token" — the form stored in mon_clients.token_hash.
	const want = "3c469e9d6c5875d37a43f353d4f88e61fcf812c66eee3457465a40b0da4153e0"
	if got := HashToken("token"); got != want {
		t.Errorf("HashToken = %q, want %q", got, want)
	}
	if got := HashToken("other"); got == want {
		t.Error("HashToken collided on different tokens")
	}
	if got := len(HashToken("")); got != 64 {
		t.Errorf("HashToken length = %d, want 64 hex characters", got)
	}
}

func TestNewEventID(t *testing.T) {
	first, err := NewEventID()
	if err != nil {
		t.Fatalf("NewEventID: %v", err)
	}
	second, err := NewEventID()
	if err != nil {
		t.Fatalf("NewEventID: %v", err)
	}
	if first == second {
		t.Fatalf("NewEventID returned %q twice", first)
	}
	parsed, err := uuid.Parse(first)
	if err != nil {
		t.Fatalf("NewEventID returned %q, which is not a UUID: %v", first, err)
	}
	if got := parsed.Version(); got != 7 {
		t.Errorf("UUID version = %d, want 7", got)
	}
	// Version 7 is time ordered, which is what the outbox relies on.
	if first > second {
		t.Errorf("ids are not time ordered: %q came before %q", first, second)
	}
}

func TestValidMonClientID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{id: "ams-1", want: true},
		{id: "MSK_2.edge", want: true},
		{id: strings.Repeat("a", 64), want: true},
		{id: strings.Repeat("a", 65)},
		{id: ""},
		{id: "ams 1"},
		{id: "ams/1"},
		{id: "амс-1"},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			if got := ValidMonClientID(tc.id); got != tc.want {
				t.Errorf("ValidMonClientID(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
	if !ValidPath(PathProxy) || !ValidPath(PathDirect) || ValidPath("tunnel") {
		t.Error("ValidPath accepts exactly proxy and direct")
	}
}
