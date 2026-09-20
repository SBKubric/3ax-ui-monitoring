package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/servertest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
)

// clearEnv unsets MON_SERVER_URL so a value exported in the shell running
// `go test` cannot leak into a test that expects the flag/env to be unset.
func clearEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envServerURL, "")
	os.Unsetenv(envServerURL)
}

// stubHTTPClientForTest points httpClientForTests at stub for the
// duration of t, restoring it afterwards — the unexported hook issue #16's
// brief calls for so `run` can be driven through a real registration
// against servertest.Stub without any CLI flag of its own.
func stubHTTPClientForTest(t *testing.T, stub *servertest.Stub) {
	t.Helper()
	old := httpClientForTests
	httpClientForTests = stub.HTTPClient()
	t.Cleanup(func() { httpClientForTests = old })
}

// waitForPollRequest waits for stub to have received a GET
// /v1/register/<id> and returns <id> — the point at which `run` has
// submitted its registration request and is now polling it, ready for a
// test to approve.
func waitForPollRequest(t *testing.T, stub *servertest.Stub) string {
	t.Helper()
	// register.Run uses a real timer for its pollAfter wait here (`run`
	// wires no Sleep override — this is production code, not
	// internal/client/register's own tests), and the stub always answers
	// 202 with a 10s pollAfter, so the first poll genuinely does not
	// happen for about 10 real seconds.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, req := range stub.Requests() {
			if req.Method == "GET" && strings.HasPrefix(req.Path, "/v1/register/") {
				return strings.TrimPrefix(req.Path, "/v1/register/")
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a registration poll request")
	return ""
}

// waitForExitCode waits for run's exit code on codeCh, failing the test if
// it takes too long — run should return promptly once its registration
// request has been approved.
func waitForExitCode(t *testing.T, codeCh <-chan int) int {
	t.Helper()
	// Approval can land just after a "pending" poll answer, in which case
	// `run` (using the real pollAfter cadence, unlike register's own
	// tests) does not notice until its *next* poll roughly 10s later.
	select {
	case code := <-codeCh:
		return code
	case <-time.After(30 * time.Second):
		t.Fatal("run did not return after approval")
		return -1
	}
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
// MON_SERVER_URL"), and that `run` carries a state-less box all the way
// through registration (issue #16) once approved.
func TestRun_ServerFromEnv(t *testing.T) {
	stub := servertest.NewStub(t)
	stubHTTPClientForTest(t, stub)
	t.Setenv(envServerURL, stub.URL())

	var stdout, stderr bytes.Buffer
	codeCh := make(chan int, 1)
	go func() { codeCh <- run([]string{"run", "--state-dir", t.TempDir()}, &stdout, &stderr) }()

	id := waitForPollRequest(t, stub)
	stub.Approve(id, "ams-1", "tok")

	if code := waitForExitCode(t, codeCh); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "registered as ams-1") {
		t.Fatalf("stdout = %q, want the registered-as log line", stdout.String())
	}
}

// TestRun_DefaultCommandIsRun checks that args starting with a flag (no
// explicit "run") are treated as `run ...` (issue #15: "run (default when
// args start with flags)"). It uses a pre-existing state file rather than
// a stub registration — dispatch to runRun is the thing under test here,
// and TestRun_ServerFromEnv/TestRun_CorruptStateIsClearedAndRegistersAgain
// already exercise the (real-timer, ~20s) registration path itself.
func TestRun_DefaultCommandIsRun(t *testing.T) {
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
	code := run([]string{"--server", "https://203.0.113.10:443", "--state-dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "state loaded (mon-client ams-1)") {
		t.Fatalf("stdout = %q, want the state-loaded log line", stdout.String())
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
// and skips registration entirely (no network call needed to reach exit 0).
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
	if !strings.Contains(stdout.String(), "registered as ams-1") {
		t.Fatalf("stdout = %q, want the registered-as log line", stdout.String())
	}
}

// TestRun_CorruptStateIsClearedAndRegistersAgain checks a present-but-
// unreadable state.json is treated as "registration required" after being
// cleared (spec §2: "стереть и регистрироваться заново"), and that `run`
// then actually completes a fresh registration against a stub.
func TestRun_CorruptStateIsClearedAndRegistersAgain(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	if _, err := state.Open(dir); err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stub := servertest.NewStub(t)
	stubHTTPClientForTest(t, stub)

	var stdout, stderr bytes.Buffer
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- run([]string{"run", "--server", stub.URL(), "--state-dir", dir}, &stdout, &stderr)
	}()

	id := waitForPollRequest(t, stub)
	stub.Approve(id, "ams-1", "tok")

	if code := waitForExitCode(t, codeCh); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no state, registration required") {
		t.Fatalf("stdout = %q, want the no-state log line", stdout.String())
	}
	if !strings.Contains(stdout.String(), "registered as ams-1") {
		t.Fatalf("stdout = %q, want the registered-as log line", stdout.String())
	}

	if _, statErr := os.Stat(filepath.Join(dir, "state.json")); statErr != nil {
		t.Fatalf("state.json should exist after registration, stat err = %v", statErr)
	}
}
