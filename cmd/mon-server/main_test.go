package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlstest"
)

// writeConfig writes a valid bootstrap configuration whose dataDir is a fresh
// temporary directory, and returns the config path and that directory.
func writeConfig(t *testing.T) (configPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")

	// A self-signed pair and tls.mode = files, so that nothing in this suite
	// can reach a certificate authority: acme-ip would make `run` ask Let's
	// Encrypt for a certificate for 203.0.113.10 the moment it starts serving.
	// Port zero keeps the listener off any port a developer may be using.
	certFile, keyFile, err := tlstest.WritePair(dir, "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"listen":   "127.0.0.1:0",
		"publicIp": "203.0.113.10",
		"dataDir":  dataDir,
		"tls": map[string]any{
			"mode": "files",
			"cert": certFile,
			"key":  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath, dataDir
}

// call runs one command line with the given standard input and returns the
// exit code with what the command printed.
func call(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// openStore opens the database the command line wrote.
func openStore(t *testing.T, dataDir string) *store.Store {
	t.Helper()
	cfg := config.Config{DataDir: dataDir}
	s, err := store.Open(cfg.DBPath(), nil)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestVersionCommand(t *testing.T) {
	code, stdout, stderr := call(t, "", "version")
	if code != exitOK {
		t.Errorf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr)
	}
	if got, want := strings.TrimSpace(stdout), version; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
	if version == "" {
		t.Error("the version variable is empty; -ldflags -X main.version has nothing to replace")
	}
}

func TestUsageAndExitCodes(t *testing.T) {
	configPath, _ := writeConfig(t)

	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "no arguments", args: nil, code: exitUsage},
		{name: "unknown command", args: []string{"serve"}, code: exitUsage},
		{name: "help", args: []string{"help"}, code: exitOK},
		{name: "-h", args: []string{"-h"}, code: exitOK},
		{name: "admin without a subcommand", args: []string{"admin", "-config", configPath}, code: exitUsage},
		{name: "admin set without a user", args: []string{"admin", "set", "-config", configPath}, code: exitUsage},
		{name: "admin set with two users", args: []string{"admin", "set", "root", "operator", "-config", configPath}, code: exitUsage},
		{name: "admin with an unknown subcommand", args: []string{"admin", "list", "-config", configPath}, code: exitUsage},
		{name: "run with an extra argument", args: []string{"run", "now", "-config", configPath}, code: exitUsage},
		{name: "run with an unknown flag", args: []string{"run", "-daemon"}, code: exitUsage},
		{name: "run with an unknown log level", args: []string{"run", "-log-level", "loud", "-config", configPath}, code: exitUsage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := call(t, "", tc.args...)
			if code != tc.code {
				t.Fatalf("exit code = %d, want %d (stdout %q, stderr %q)", code, tc.code, stdout, stderr)
			}
			if !strings.Contains(stdout+stderr, "Usage:") && tc.code == exitUsage {
				t.Errorf("a usage error printed no usage text: %q", stdout+stderr)
			}
		})
	}
}

func TestRunRejectsAnInvalidConfiguration(t *testing.T) {
	// A config file without publicIp cannot be served over acme-ip.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	body := `{"dataDir": "` + filepath.Join(dir, "data") + `"}`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	code, _, stderr := call(t, "", "run", "-config", configPath)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, "invalid configuration") {
		t.Errorf("stderr = %q, want it to explain the invalid configuration", stderr)
	}
}

func TestAdminSetWritesTheAdministrator(t *testing.T) {
	configPath, dataDir := writeConfig(t)

	code, stdout, stderr := call(t, "s3cret\ns3cret\n", "admin", "set", "root", "-config", configPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr)
	}
	if !strings.Contains(stdout, `admin user "root" updated`) {
		t.Errorf("stdout = %q, want a confirmation naming the user", stdout)
	}
	if !strings.Contains(stderr, "Password for root:") || !strings.Contains(stderr, "Repeat password:") {
		t.Errorf("prompts = %q, want both password prompts", stderr)
	}

	s := openStore(t, dataDir)
	ok, err := s.CheckAdmin("root", "s3cret")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Error("the stored administrator does not accept the password that was typed")
	}
	if ok, err := s.CheckAdmin("root", "s3cret "); err != nil || ok {
		t.Errorf("CheckAdmin with a wrong password = %v, %v, want false, nil", ok, err)
	}
	row, _, err := s.Admin()
	if err != nil {
		t.Fatalf("Admin: %v", err)
	}
	if strings.Contains(row.PasswordHash, "s3cret") || !strings.HasPrefix(row.PasswordHash, "$2") {
		t.Errorf("password hash = %q, want a bcrypt hash", row.PasswordHash)
	}
}

func TestAdminSetRepeatReplacesLoginAndPassword(t *testing.T) {
	configPath, dataDir := writeConfig(t)

	if code, _, stderr := call(t, "first\nfirst\n", "admin", "set", "root", "-config", configPath); code != exitOK {
		t.Fatalf("first call: exit %d (stderr %q)", code, stderr)
	}
	// The flag may also come before the subcommand.
	if code, _, stderr := call(t, "second\nsecond\n", "admin", "-config", configPath, "set", "operator"); code != exitOK {
		t.Fatalf("second call: exit %d (stderr %q)", code, stderr)
	}

	s := openStore(t, dataDir)
	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "new login", username: "operator", password: "second", want: true},
		{name: "old login", username: "root", password: "first"},
		{name: "old login with the new password", username: "root", password: "second"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CheckAdmin(tc.username, tc.password)
			if err != nil {
				t.Fatalf("CheckAdmin: %v", err)
			}
			if got != tc.want {
				t.Errorf("CheckAdmin(%q, %q) = %v, want %v", tc.username, tc.password, got, tc.want)
			}
		})
	}
}

func TestAdminSetRefusesBadInput(t *testing.T) {
	tests := []struct {
		name   string
		stdin  string
		stderr string
	}{
		{name: "the two passwords differ", stdin: "one\ntwo\n", stderr: "do not match"},
		{name: "an empty password", stdin: "\n\n", stderr: "password is empty"},
		{name: "no input at all", stdin: "", stderr: "no input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath, dataDir := writeConfig(t)
			code, _, stderr := call(t, tc.stdin, "admin", "set", "root", "-config", configPath)
			if code != exitError {
				t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitError, stderr)
			}
			if !strings.Contains(stderr, tc.stderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.stderr)
			}
			if _, ok, err := openStore(t, dataDir).Admin(); err != nil || ok {
				t.Errorf("an administrator was written anyway: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestServeOpensTheStoreAndStopsWithTheContext(t *testing.T) {
	cfg := config.Config{Listen: ":8443", PublicIP: "203.0.113.10", DataDir: filepath.Join(t.TempDir(), "data"), TLS: config.TLS{Mode: config.TLSModeACMEIP}}
	log := newLogger(&bytes.Buffer{}, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, log) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after the context was cancelled")
	}

	if _, err := os.Stat(cfg.DBPath()); err != nil {
		t.Fatalf("serve did not create the database: %v", err)
	}
	s := openStore(t, cfg.DataDir)
	if _, err := s.Settings(); err != nil {
		t.Errorf("the database serve created is not migrated: %v", err)
	}
}

func TestServeReportsAnUnusableDataDirectory(t *testing.T) {
	// A file where the data directory should be: the store cannot be opened.
	dir := t.TempDir()
	blocked := filepath.Join(dir, "data")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	cfg := config.Config{Listen: ":8443", PublicIP: "203.0.113.10", DataDir: blocked, TLS: config.TLS{Mode: config.TLSModeACMEIP}}

	if err := serve(context.Background(), cfg, newLogger(&bytes.Buffer{}, 0)); err == nil {
		t.Fatal("serve succeeded with an unusable data directory")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "debug", in: "debug"},
		{name: "info", in: "INFO"},
		{name: "warn", in: " warn "},
		{name: "warning", in: "warning"},
		{name: "error", in: "error"},
		{name: "empty means info", in: ""},
		{name: "unknown", in: "loud", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseLevel(tc.in)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("parseLevel(%q) error = %v, want error %v", tc.in, err, tc.wantErr)
			}
		})
	}
}
