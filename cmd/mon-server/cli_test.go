package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// clearEnv unsets every MON_* variable the CLI reads (mirroring
// internal/config's own clearEnv), so a MON_DATA_DIR or MON_LISTEN exported
// in the shell running `go test` cannot redirect these tests at a real
// database or listen address.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"MON_LISTEN",
		"MON_PUBLIC_IP",
		"MON_DATA_DIR",
		"MON_TLS_MODE",
		"MON_TLS_CERT",
		"MON_TLS_KEY",
		envAdminPassword,
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// writeTestConfig writes a bootstrap config file pointing dataDir at a fresh
// temp directory, so `run`/`admin set` open a throwaway database instead of
// touching /var/lib/mon-server.
func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := map[string]any{
		"listen":  ":8443",
		"dataDir": dir,
		"tls":     map[string]any{"mode": "files", "cert": "c.pem", "key": "k.pem"},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestRun_Version checks that `mon-server version` prints the expected line
// on stdout and exits 0.
func TestRun_Version(t *testing.T) {
	clearEnv(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	want := "mon-server dev\n"
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestRun_AdminSetViaEnv checks the non-interactive path: MON_ADMIN_PASSWORD
// lets `admin set` run without a terminal, and the resulting store accepts
// the credentials it just wrote.
func TestRun_AdminSetViaEnv(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)
	t.Setenv("MON_ADMIN_PASSWORD", "s3cret-password")

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "alice") {
		t.Fatalf("stdout = %q, want it to mention the username", stdout.String())
	}

	dir := filepath.Dir(configPath)
	st, err := store.Open(filepath.Join(dir, "mon-server.db"))
	if err != nil {
		t.Fatalf("open store written by admin set: %v", err)
	}
	ok, err := st.CheckAdmin("alice", "s3cret-password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Fatal("CheckAdmin(alice, s3cret-password) after admin set: want true, got false")
	}
}

// TestRun_AdminSetEmptyEnvPasswordFails checks that an explicitly empty
// MON_ADMIN_PASSWORD is refused rather than silently treated as "prompt
// instead" or "set an empty password".
func TestRun_AdminSetEmptyEnvPasswordFails(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)
	t.Setenv("MON_ADMIN_PASSWORD", "")

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for empty MON_ADMIN_PASSWORD (stdout: %s)", stdout.String())
	}
}

// TestRun_AdminSetPipedPasswordMatches checks the interactive (non-terminal)
// prompt path end to end: two matching lines piped on stdin must succeed,
// with the resulting store accepting the password that was typed — this is
// the exact shape `printf 'pw\npw\n' | mon-server admin set alice` takes,
// which used to always fail "passwords did not match" because a fresh
// bufio.Reader per prompt made the first read consume both lines.
func TestRun_AdminSetPipedPasswordMatches(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader("pw\npw\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	dir := filepath.Dir(configPath)
	st, err := store.Open(filepath.Join(dir, "mon-server.db"))
	if err != nil {
		t.Fatalf("open store written by admin set: %v", err)
	}
	ok, err := st.CheckAdmin("alice", "pw")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Fatal("CheckAdmin(alice, pw) after piped admin set: want true, got false")
	}
}

// TestRun_AdminSetPipedPasswordMismatch checks the other half: two
// different lines piped on stdin must be rejected with the mismatch
// message, not succeed by accident or fail with some unrelated EOF error.
func TestRun_AdminSetPipedPasswordMismatch(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader("pw\nother\n"), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for mismatched passwords (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "passwords did not match") {
		t.Fatalf("stderr = %q, want the mismatch message", stderr.String())
	}
}

// TestRun_UnknownCommand checks that an unrecognised subcommand exits
// non-zero with a usage message, instead of silently doing nothing.
func TestRun_UnknownCommand(t *testing.T) {
	clearEnv(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an unknown command")
	}
	if !strings.Contains(stderr.String(), "bogus") {
		t.Fatalf("stderr = %q, want it to mention the bad command", stderr.String())
	}
}

// TestRun_FailsFastOnInvalidConfigWithoutStartingAnything checks that a
// config which fails Validate (here: acme-ip mode with no publicIp) is
// rejected before `run` ever opens the store or attempts to build TLS/bind a
// listener — a bad config must fail loudly and immediately, not partially
// start something it then has no clean way to tear down.
func TestRun_FailsFastOnInvalidConfigWithoutStartingAnything(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	cfg := map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": dir,
		"tls":     map[string]any{"mode": "acme-ip"}, // no publicIp: Validate must reject this
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "-config", configPath}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatal("exit code = 0, want non-zero for an invalid config")
	}

	if _, err := os.Stat(filepath.Join(dir, "mon-server.db")); err == nil {
		t.Fatal("mon-server.db was created: want config validation to fail before the store is ever opened")
	}
}

// syncBuffer is a bytes.Buffer safe for the concurrent read (test goroutine)
// and write (the run() call in its own goroutine) that
// TestRun_RunServesAndShutsDownOnSignal needs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestRunCtx_RunServesAndShutsDownWhenCtxCancelled is the end-to-end
// exercise of the whole "run" subcommand: a valid "files"-mode config
// listening on an OS-assigned loopback port (127.0.0.1:0) brings up a real
// HTTPS listener (proven by a successful /healthz request against the
// self-signed cert tlsxtest hands out), and cancelling the ctx passed to
// runCtx — standing in for the SIGINT/SIGTERM a real deployment would send —
// makes it shut down cleanly with exit code 0, instead of hanging forever or
// dying uncleanly. Driving this through ctx cancellation instead of a real
// self-sent signal removes the previous version's two flaky ingredients: a
// freeLoopbackAddr probe port that could be stolen by another process
// before `run` rebound it, and a self-SIGTERM racing whatever else in this
// test binary might be handling signals. It also checks the coverage a
// deleted placeholder test used to provide: that `run` actually leaves
// mon-server.db behind in dataDir.
func TestRunCtx_RunServesAndShutsDownWhenCtxCancelled(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)
	cfg := map[string]any{
		"listen":   "127.0.0.1:0",
		"publicIp": "127.0.0.1",
		"dataDir":  dir,
		"tls":      map[string]any{"mode": "files", "cert": certPath, "key": keyPath},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	onListen := func(addr string) { addrCh <- addr }

	var stdout, stderr syncBuffer
	codeCh := make(chan int, 1)
	go func() {
		codeCh <- runCtx(ctx, []string{"run", "-config", configPath}, strings.NewReader(""), &stdout, &stderr, onListen)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("onListen was never called")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	// Poll /healthz until the listener actually accepts connections (it was
	// bound by the time onListen fired, but ServeTLS starts serving from a
	// separate goroutine).
	deadline := time.Now().Add(5 * time.Second)
	var healthy bool
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !healthy {
		t.Fatalf("GET /healthz never returned 200 (stderr so far: %s)", stderr.String())
	}

	cancel()

	select {
	case code := <-codeCh:
		if code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not return after ctx was cancelled")
	}

	if _, err := os.Stat(filepath.Join(dir, "mon-server.db")); err != nil {
		t.Fatalf("mon-server.db: %v, want it to exist after run returns", err)
	}
}

// TestRun_AdminSetFlagAfterSubcommandIsNotUsername checks that
// `admin set -config /x alice` parses -config as a flag and "alice" as the
// username, instead of taking args[1] literally and creating an admin
// account literally named "-config".
func TestRun_AdminSetFlagAfterSubcommandIsNotUsername(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)
	t.Setenv("MON_ADMIN_PASSWORD", "s3cret-password")

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}

	dir := filepath.Dir(configPath)
	st, err := store.Open(filepath.Join(dir, "mon-server.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ok, err := st.CheckAdmin("alice", "s3cret-password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Fatal("CheckAdmin(alice, ...) after `admin set -config <path> alice`: want true, got false")
	}
	ok, err = st.CheckAdmin("-config", "s3cret-password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if ok {
		t.Fatal(`CheckAdmin("-config", ...) matched: want no admin ever named "-config"`)
	}
}

// TestRun_AdminSetNoUsernameFails checks that `admin set` with no positional
// argument at all is a usage error, not a call into the store with an empty
// or garbage username.
func TestRun_AdminSetNoUsernameFails(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for admin set with no username (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Fatalf("stderr = %q, want a usage message", stderr.String())
	}
}

// TestRun_AdminSetUsernameLooksLikeFlagFails checks that a positional
// argument starting with "-" is rejected as a username outright, even once
// it has correctly survived flag parsing as the sole positional argument
// (e.g. an unrecognised flag typo'd after the real ones, or a username an
// operator mistakenly quoted with a leading dash).
func TestRun_AdminSetUsernameLooksLikeFlagFails(t *testing.T) {
	clearEnv(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "--", "-alice"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for a username starting with '-' (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Fatalf("stderr = %q, want a usage message", stderr.String())
	}
}

// TestRun_AdminSetExtraArgFails checks that a second positional argument
// after the username (e.g. a typo'd extra word) is rejected rather than
// silently ignored.
func TestRun_AdminSetExtraArgFails(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)
	t.Setenv("MON_ADMIN_PASSWORD", "s3cret-password")

	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice", "extra"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for a trailing extra argument (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Fatalf("stderr = %q, want a usage message", stderr.String())
	}
}

// TestRun_RunExtraArgFails checks that `run extra` (an unexpected positional
// argument to a command that takes none) is rejected instead of silently
// starting up anyway.
func TestRun_RunExtraArgFails(t *testing.T) {
	clearEnv(t)
	configPath := writeTestConfig(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "-config", configPath, "extra"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero for `run extra` (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage") {
		t.Fatalf("stderr = %q, want a usage message", stderr.String())
	}
}

// TestRun_AdminSetPromptsAfterStoreOpenFailure checks the ordering fix: when
// the store cannot be opened (here, dataDir is a file, not a directory, so
// MkdirAll/open both fail), `admin set` must fail before ever prompting for
// a password — a caller feeding it stdin only for the password prompt must
// not be required to satisfy a prompt that should never happen.
func TestRun_AdminSetPromptsAfterStoreOpenFailure(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	blockedDataDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blockedDataDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	cfg := map[string]any{
		"listen":  ":8443",
		"dataDir": blockedDataDir,
		"tls":     map[string]any{"mode": "files", "cert": "c.pem", "key": "k.pem"},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// stdin has nothing on it: if runAdmin prompted before opening the
	// store, readPassword would hit EOF and this would fail for the wrong
	// reason (or hang, without the empty reader). It must instead fail at
	// "open store" and never reach the prompt.
	var stdout, stderr bytes.Buffer
	code := run([]string{"admin", "set", "-config", configPath, "alice"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero when the store cannot be opened (stdout: %s)", stdout.String())
	}
	if !strings.Contains(stderr.String(), "open store") {
		t.Fatalf("stderr = %q, want it to fail at opening the store, not the password prompt", stderr.String())
	}
}
