package store

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// wantTables is every table this step's migration must create (spec §3).
// Later steps add rows to these tables but must never rename or drop one —
// this list is the contract they build on.
var wantTables = []string{
	"settings",
	"admin",
	"admin_sessions",
	"login_attempts",
	"registration_requests",
	"mon_clients",
	"targets",
	"panel_inbounds",
	"client_configs",
	"events_outbox",
	"stats_buckets",
	"probe_seen",
}

// wantIndexes is every idx_ms_-prefixed index the migration must create,
// including the three unique composite keys spec §3 calls out by name:
// targets(mon_client_id, inbound_kind, inbound_id, path), stats_buckets(...,
// bucket_start) and panel_inbounds(inbound_kind, inbound_id).
var wantIndexes = []string{
	"idx_ms_admin_sessions_expires_at",
	"idx_ms_registration_requests_status_created",
	"idx_ms_mon_clients_token_hash",
	"idx_ms_mon_clients_enabled",
	"idx_ms_targets_key",
	"idx_ms_panel_inbounds_key",
	"idx_ms_events_outbox_sent_at",
	"idx_ms_stats_buckets_key",
	"idx_ms_stats_buckets_sent_at",
	"idx_ms_probe_seen_seen_at",
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mon-server.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

type sqliteObject struct {
	Name    string
	TblName string
}

func listTables(t *testing.T, s *Store) []string {
	t.Helper()
	var rows []sqliteObject
	if err := s.DB.Raw(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).Scan(&rows).Error; err != nil {
		t.Fatalf("list tables: %v", err)
	}
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Name
	}
	return names
}

func listMsIndexes(t *testing.T, s *Store) []string {
	t.Helper()
	var rows []sqliteObject
	if err := s.DB.Raw(`SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_ms_%'`).Scan(&rows).Error; err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Name
	}
	return names
}

// TestMigrate_CreatesEveryTableAndIndex checks that Migrate, run on an empty
// database, produces exactly the tables and idx_ms_ indexes spec §3
// requires — the contract every later step's package depends on by name.
func TestMigrate_CreatesEveryTableAndIndex(t *testing.T) {
	s := openTestStore(t)

	tables := listTables(t, s)
	for _, want := range wantTables {
		if !slices.Contains(tables, want) {
			t.Errorf("missing table %q (have %v)", want, tables)
		}
	}

	indexes := listMsIndexes(t, s)
	for _, want := range wantIndexes {
		if !slices.Contains(indexes, want) {
			t.Errorf("missing index %q (have %v)", want, indexes)
		}
	}
}

// TestMigrate_Idempotent checks that running Migrate a second time against an
// already-current database succeeds and changes nothing — every process
// start calls Open, which calls Migrate unconditionally (see Open's doc
// comment), so this must never fail on an existing install.
func TestMigrate_Idempotent(t *testing.T) {
	s := openTestStore(t)

	before := listTables(t, s)
	beforeIdx := listMsIndexes(t, s)

	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	after := listTables(t, s)
	afterIdx := listMsIndexes(t, s)

	slices.Sort(before)
	slices.Sort(after)
	slices.Sort(beforeIdx)
	slices.Sort(afterIdx)

	if !slices.Equal(before, after) {
		t.Fatalf("tables changed after second Migrate: before=%v after=%v", before, after)
	}
	if !slices.Equal(beforeIdx, afterIdx) {
		t.Fatalf("indexes changed after second Migrate: before=%v after=%v", beforeIdx, afterIdx)
	}
}

// TestOpen_ForeignKeysPragmaOn checks that Open's DSN actually turns foreign
// key enforcement on (spec §3: "foreign_keys=ON") rather than leaving
// SQLite's default of off, which would let later steps silently orphan rows.
func TestOpen_ForeignKeysPragmaOn(t *testing.T) {
	s := openTestStore(t)

	var on int
	if err := s.DB.Raw("PRAGMA foreign_keys").Scan(&on).Error; err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if on != 1 {
		t.Fatalf("foreign_keys pragma = %d, want 1", on)
	}
}

// TestTargets_UniqueKeyRejectsDuplicate checks that the composite unique
// index actually enforces uniqueness, not just that sqlite_master lists it —
// an index gorm created with the wrong columns would still show up by name.
func TestTargets_UniqueKeyRejectsDuplicate(t *testing.T) {
	s := openTestStore(t)

	base := Target{MonClientId: "msk-1", InboundKind: InboundKindXray, InboundId: 1, Path: PathDirect, State: TargetUnknown}
	if err := s.DB.Create(&base).Error; err != nil {
		t.Fatalf("create first target: %v", err)
	}
	dup := Target{MonClientId: "msk-1", InboundKind: InboundKindXray, InboundId: 1, Path: PathDirect, State: TargetUnknown}
	if err := s.DB.Create(&dup).Error; err == nil {
		t.Fatal("create duplicate target: want error, got nil")
	}
}

// TestStatsBuckets_UniqueKeyRejectsDuplicate mirrors
// TestTargets_UniqueKeyRejectsDuplicate for the five-column stats_buckets
// key, which additionally includes bucket_start.
func TestStatsBuckets_UniqueKeyRejectsDuplicate(t *testing.T) {
	s := openTestStore(t)

	base := StatsBucket{MonClientId: "msk-1", InboundKind: InboundKindAwg, InboundId: 0, Path: PathProxy, BucketStart: 1_700_000_000_000}
	if err := s.DB.Create(&base).Error; err != nil {
		t.Fatalf("create first bucket: %v", err)
	}
	dup := StatsBucket{MonClientId: "msk-1", InboundKind: InboundKindAwg, InboundId: 0, Path: PathProxy, BucketStart: 1_700_000_000_000}
	if err := s.DB.Create(&dup).Error; err == nil {
		t.Fatal("create duplicate bucket: want error, got nil")
	}
}

// TestPanelInbounds_UniqueKeyRejectsDuplicate mirrors the same check for
// panel_inbounds(inbound_kind, inbound_id).
func TestPanelInbounds_UniqueKeyRejectsDuplicate(t *testing.T) {
	s := openTestStore(t)

	base := PanelInbound{InboundKind: InboundKindXray, InboundId: 5}
	if err := s.DB.Create(&base).Error; err != nil {
		t.Fatalf("create first panel inbound: %v", err)
	}
	dup := PanelInbound{InboundKind: InboundKindXray, InboundId: 5}
	if err := s.DB.Create(&dup).Error; err == nil {
		t.Fatal("create duplicate panel inbound: want error, got nil")
	}
}

// TestMonClient_PathsRoundTrip checks the PathsList/SetPaths pair spec §3
// requires as the only way callers touch the JSON-encoded paths column.
func TestMonClient_PathsRoundTrip(t *testing.T) {
	mc := &MonClient{Id: "msk-1"}
	mc.SetPaths([]string{PathProxy, PathDirect})

	if mc.Paths != `["proxy","direct"]` {
		t.Fatalf("Paths = %q, want JSON array", mc.Paths)
	}

	got := mc.PathsList()
	want := []string{PathProxy, PathDirect}
	if !slices.Equal(got, want) {
		t.Fatalf("PathsList() = %v, want %v", got, want)
	}
}

// TestMonClient_CreateWithEnabledFalse guards against gorm's bool-default
// trap: a gorm "default:true" tag on a bool column makes Create silently
// replace an explicit false with true, because Go's zero value for bool
// (false) is indistinguishable from "field not set". MonClient.Enabled must
// not carry that tag, or a client created disabled would come back enabled.
func TestMonClient_CreateWithEnabledFalse(t *testing.T) {
	s := openTestStore(t)

	mc := &MonClient{Id: "msk-1", Name: "msk-1", Enabled: false}
	mc.SetPaths(nil)
	if err := s.DB.Create(mc).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got MonClient
	if err := s.DB.First(&got, "id = ?", "msk-1").Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Enabled {
		t.Fatal("Enabled = true after Create(Enabled: false), want false")
	}
}

// TestPanelInbound_CreateWithEnableFalse mirrors
// TestMonClient_CreateWithEnabledFalse for PanelInbound.Enable.
func TestPanelInbound_CreateWithEnableFalse(t *testing.T) {
	s := openTestStore(t)

	pi := &PanelInbound{InboundKind: InboundKindXray, InboundId: 12, Enable: false}
	if err := s.DB.Create(pi).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got PanelInbound
	if err := s.DB.First(&got, "inbound_kind = ? AND inbound_id = ?", InboundKindXray, 12).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Enable {
		t.Fatal("Enable = true after Create(Enable: false), want false")
	}
}

// TestAdmin_UpdatedAtNotAutoStamped guards against gorm's auto-timestamp
// trap: a bare int64 field literally named UpdatedAt is auto-tracked by
// gorm's callbacks via a plain time.Now() in Unix seconds unless the tag
// says autoUpdateTime:false, which would bypass internal/clock and store a
// value in the wrong unit (seconds, not spec §3's ms). This checks that an
// Updates call does not silently rewrite updated_at out from under a caller
// that set it explicitly (e.g. SetAdmin via Store.Clock).
func TestAdmin_UpdatedAtNotAutoStamped(t *testing.T) {
	s := openTestStore(t)

	admin := &Admin{Id: adminRowId, Username: "alice", PasswordHash: "hash", UpdatedAt: 1_700_000_000_000}
	if err := s.DB.Create(admin).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.DB.Model(&Admin{}).Where("id = ?", adminRowId).Update("username", "bob").Error; err != nil {
		t.Fatalf("update username: %v", err)
	}

	var got Admin
	if err := s.DB.First(&got, "id = ?", adminRowId).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.UpdatedAt != 1_700_000_000_000 {
		t.Fatalf("UpdatedAt = %d after unrelated Update, want unchanged 1700000000000", got.UpdatedAt)
	}
}

// TestAdminSession_CreatedAtExactMsValue guards against the same
// auto-timestamp trap for AdminSession.CreatedAt: it must store exactly the
// ms UTC value the caller supplies, not a value gorm stamped itself in Unix
// seconds.
func TestAdminSession_CreatedAtExactMsValue(t *testing.T) {
	s := openTestStore(t)

	const createdAtMs = 1_700_000_000_123
	sess := &AdminSession{Id: "sess-1", CreatedAt: createdAtMs, ExpiresAt: createdAtMs + 86_400_000}
	if err := s.DB.Create(sess).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var got AdminSession
	if err := s.DB.First(&got, "id = ?", "sess-1").Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.CreatedAt != createdAtMs {
		t.Fatalf("CreatedAt = %d, want exact ms value %d", got.CreatedAt, createdAtMs)
	}
}

// TestOpen_CreatesMissingDataDir checks that Open creates the file's parent
// directory when it does not exist yet — sqlite creates the database file
// itself but not the directory it lives in, so a fresh box's dataDir must be
// created by Open, not assumed to already exist.
func TestOpen_CreatesMissingDataDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "t.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open with missing parent dirs: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected db file to exist: %v", err)
	}
	_ = s
}
