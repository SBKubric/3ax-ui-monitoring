package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
)

// clearEnv unsets MON_SERVER_URL so a value exported in the shell running
// `go test` cannot leak into a test that expects the flag/env to be unset.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envServerURL, "")
	os.Unsetenv(envServerURL)
}

// TestRun_Version checks `mon-client version` prints the expected line and
// exits 0.
func TestRun_Version(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if want := "mon-client dev\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestRun_NoServerIsUsageError checks issue #15's requirement that --server
// (or MON_SERVER_URL) is the one mandatory parameter: missing it is a
// usage error (exit 2), not a runtime failure.
func TestRun_NoServerIsUsageError(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "--state-dir", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--server") {
		t.Fatalf("stderr = %q, want it to mention --server", stderr.String())
	}
}

// TestRun_NoArgsIsUsageError checks bare `mon-client` with nothing at all.
func TestRun_NoArgsIsUsageError(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// TestRun_ServerFromEnv checks MON_SERVER_URL satisfies the requirement
// exactly like --server does (spec §2: "через флаг --server или ENV
// MON_SERVER_URL").
func TestRun_ServerFromEnv(t *testing.T) {
	t.Setenv(envServerURL, "https://203.0.113.10:443")
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "--state-dir", t.TempDir()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no state, registration required") {
		t.Fatalf("stdout = %q, want the no-state log line", stdout.String())
	}
}

// TestRun_DefaultCommandIsRun checks that args starting with a flag (no
// explicit "run") are treated as `run ...` (issue #15: "run (default when
// args start with flags)").
func TestRun_DefaultCommandIsRun(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--server", "https://203.0.113.10:443", "--state-dir", t.TempDir()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no state, registration required") {
		t.Fatalf("stdout = %q, want the no-state log line", stdout.String())
	}
}

// TestRun_UnknownCommandIsUsageError checks an unrecognised first argument
// that does not look like a flag.
func TestRun_UnknownCommandIsUsageError(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"frobnicate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// TestRun_InvalidLogLevelIsUsageError checks --log-level only accepts the
// four documented spellings.
func TestRun_InvalidLogLevelIsUsageError(t *testing.T) {
	clearEnv(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "--server", "https://x", "--state-dir", t.TempDir(), "--log-level", "verbose"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}

// TestRun_StateLoadedLogsMonClientID checks the other half of issue #15's
// log requirement: an existing, valid state.json logs the mon-client id
// instead of "registration required".
func TestRun_StateLoadedLogsMonClientID(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	d, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := d.Save(&state.File{MonClientID: "ams-1", Token: "tok", ServerURL: "https://x", AppliedRevision: "rev1"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "--server", "https://x", "--state-dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "state loaded (mon-client ams-1)") {
		t.Fatalf("stdout = %q, want the state-loaded log line", stdout.String())
	}
}

// TestRun_CorruptStateIsClearedAndLogsRegistrationRequired checks a
// present-but-unreadable state.json is treated as "registration required"
// after being cleared, per spec §2's "стереть и регистрироваться заново".
func TestRun_CorruptStateIsClearedAndLogsRegistrationRequired(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	if _, err := state.Open(dir); err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "--server", "https://x", "--state-dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no state, registration required") {
		t.Fatalf("stdout = %q, want the no-state log line", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("state.json should have been removed, stat err = %v", err)
	}
}
