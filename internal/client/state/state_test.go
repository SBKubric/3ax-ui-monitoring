package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_CreatesDirAt0700 checks Open makes a missing state directory at
// the mode spec §2 requires for a secret-holding directory.
func TestOpen_CreatesDirAt0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mon-client")
	if _, err := Open(dir); err != nil {
		t.Fatalf("Open: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("Open did not create a directory")
	}
	if got := fi.Mode().Perm(); got != dirMode {
		t.Fatalf("dir mode = %o, want %o", got, dirMode)
	}
}

// TestLoad_MissingIsErrNoState checks issue #15's acceptance criterion: no
// state file means "registration required", not a generic I/O error.
func TestLoad_MissingIsErrNoState(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := d.Load(); !errors.Is(err, ErrNoState) {
		t.Fatalf("Load() error = %v, want ErrNoState", err)
	}
}

// TestSaveLoad_RoundTrip checks issue #15's other acceptance criterion:
// state.json round-trips every field.
func TestSaveLoad_RoundTrip(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	want := &File{
		MonClientID:     "ams-1",
		Token:           "s3cr3t-token",
		ServerURL:       "https://203.0.113.10:443",
		AppliedRevision: "3a91c0de77b1f2e4",
	}
	if err := d.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := d.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if *got != *want {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}
}

// TestSave_FileMode0600 checks the state file's permission bits directly —
// issue #15's "права файла 0600".
func TestSave_FileMode0600(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Save(&File{MonClientID: "ams-1", Token: "x", ServerURL: "https://x", AppliedRevision: "y"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(d.Path(stateFileName))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != fileMode {
		t.Fatalf("file mode = %o, want %o", got, fileMode)
	}
}

// TestSave_OverExistingKeeps0600 checks that overwriting an already-saved
// state.json (the normal case: appliedRevision changes on every config
// application) does not regress the permission bits, since Save always
// goes through a fresh temp file rather than truncating the old one.
func TestSave_OverExistingKeeps0600(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	f := &File{MonClientID: "ams-1", Token: "x", ServerURL: "https://x", AppliedRevision: "rev1"}
	if err := d.Save(f); err != nil {
		t.Fatalf("Save #1: %v", err)
	}
	f.AppliedRevision = "rev2"
	if err := d.Save(f); err != nil {
		t.Fatalf("Save #2: %v", err)
	}
	fi, err := os.Stat(d.Path(stateFileName))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != fileMode {
		t.Fatalf("file mode after overwrite = %o, want %o", got, fileMode)
	}
	got, err := d.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AppliedRevision != "rev2" {
		t.Fatalf("AppliedRevision = %q, want %q", got.AppliedRevision, "rev2")
	}
}

// TestLoad_CorruptIsError checks a corrupt state.json fails Load with a
// plain error rather than ErrNoState, so a caller cannot mistake "the file
// is garbage" for "the file was never written" — spec §2 leaves the
// "clear and re-register" decision to the caller, but only once it knows
// the difference.
func TestLoad_CorruptIsError(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := os.WriteFile(d.Path(stateFileName), []byte("{not json"), fileMode); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err = d.Load()
	if err == nil {
		t.Fatalf("Load() error = nil, want a decode error")
	}
	if errors.Is(err, ErrNoState) {
		t.Fatalf("Load() error = ErrNoState, want a distinct decode error")
	}
}

// TestClear_RemovesOnlyStateFile checks Clear leaves other working files
// (cycles.json) untouched — protocol §2.3/§5.3's revoke/401 path only
// forgets the registration, not the probe buffer.
func TestClear_RemovesOnlyStateFile(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Save(&File{MonClientID: "ams-1", Token: "x", ServerURL: "https://x", AppliedRevision: "y"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(d.Path("cycles.json"), []byte("[]"), fileMode); err != nil {
		t.Fatalf("WriteFile cycles.json: %v", err)
	}

	if err := d.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := d.Load(); !errors.Is(err, ErrNoState) {
		t.Fatalf("Load() after Clear = %v, want ErrNoState", err)
	}
	if _, err := os.Stat(d.Path("cycles.json")); err != nil {
		t.Fatalf("cycles.json should survive Clear: %v", err)
	}
}

// TestClear_MissingIsNotAnError checks Clear is idempotent: calling it when
// there is nothing to clear (e.g. a box that never finished registering)
// must not itself be an error.
func TestClear_MissingIsNotAnError(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := d.Clear(); err != nil {
		t.Fatalf("Clear on empty dir: %v", err)
	}
}
