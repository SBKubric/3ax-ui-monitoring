package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearEnv unsets every MON_* variable this package reads, so tests do not
// leak state into each other via the process environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envListen, envPublicIP, envDataDir, envTLSMode, envTLSCert, envTLSKey} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func writeConfigFile(t *testing.T, cfg Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestLoad_DefaultMissingFileUsesDefaults checks that a missing bootstrap
// path is not an error when it is the built-in default (explicit=false, as
// when no -config flag was given): an install with only ENV variables (e.g.
// a container that never mounts /etc/mon-server/config.json) must still
// start.
func TestLoad_DefaultMissingFileUsesDefaults(t *testing.T) {
	clearEnv(t)

	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"), false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := &Config{
		Listen:  DefaultListen,
		DataDir: DefaultDataDir,
		TLS:     TLSConfig{Mode: DefaultTLSMode},
	}
	if *cfg != *want {
		t.Fatalf("Load() = %+v, want %+v", cfg, want)
	}
}

// TestLoad_ExplicitMissingFileErrors checks the other half of the same rule:
// a path the caller named explicitly (explicit=true, as when -config was
// given) must fail loudly if it does not exist, rather than silently falling
// back to defaults and starting the process against the wrong settings.
func TestLoad_ExplicitMissingFileErrors(t *testing.T) {
	clearEnv(t)

	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"), true)
	if err == nil {
		t.Fatal("Load() with explicit missing path: want error, got nil")
	}
}

// TestLoad_UnknownFieldErrors checks that an unrecognised key in the config
// file is a hard error naming the key, not silently dropped — a typo'd field
// name (or a value that actually belongs in the settings table, §9.4) must
// not look like it took effect when it did nothing.
func TestLoad_UnknownFieldErrors(t *testing.T) {
	clearEnv(t)

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"public_ip": "203.0.113.10"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("Load() with unknown field: want error, got nil")
	}
	if !strings.Contains(err.Error(), "public_ip") {
		t.Fatalf("Load() error = %q, want it to name the unknown field", err.Error())
	}
}

// TestLoad_FileOnly checks that a value present only in the JSON file
// overrides the built-in default.
func TestLoad_FileOnly(t *testing.T) {
	clearEnv(t)

	path := writeConfigFile(t, Config{
		Listen:   ":8443",
		PublicIP: "203.0.113.10",
		DataDir:  "/data/mon",
		TLS:      TLSConfig{Mode: TLSModeFiles, Cert: "/certs/c.pem", Key: "/certs/k.pem"},
	})

	cfg, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8443" || cfg.PublicIP != "203.0.113.10" || cfg.DataDir != "/data/mon" {
		t.Fatalf("Load() = %+v, want file values", cfg)
	}
	if cfg.TLS.Mode != TLSModeFiles || cfg.TLS.Cert != "/certs/c.pem" || cfg.TLS.Key != "/certs/k.pem" {
		t.Fatalf("Load() TLS = %+v, want file values", cfg.TLS)
	}
}

// TestLoad_EnvOnly checks that MON_* variables apply on top of defaults when
// no file is present.
func TestLoad_EnvOnly(t *testing.T) {
	clearEnv(t)
	t.Setenv(envListen, ":9443")
	t.Setenv(envPublicIP, "198.51.100.5")
	t.Setenv(envDataDir, "/var/lib/mon2")
	t.Setenv(envTLSMode, TLSModeFiles)
	t.Setenv(envTLSCert, "/env/c.pem")
	t.Setenv(envTLSKey, "/env/k.pem")

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.json"), false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":9443" || cfg.PublicIP != "198.51.100.5" || cfg.DataDir != "/var/lib/mon2" {
		t.Fatalf("Load() = %+v, want ENV values", cfg)
	}
	if cfg.TLS.Mode != TLSModeFiles || cfg.TLS.Cert != "/env/c.pem" || cfg.TLS.Key != "/env/k.pem" {
		t.Fatalf("Load() TLS = %+v, want ENV values", cfg.TLS)
	}
}

// TestLoad_EnvWinsOverFile checks the documented priority: ENV overrides a
// value the file also sets, field by field, rather than replacing the whole
// file wholesale.
func TestLoad_EnvWinsOverFile(t *testing.T) {
	clearEnv(t)
	path := writeConfigFile(t, Config{
		Listen:   ":8443",
		PublicIP: "203.0.113.10",
		DataDir:  "/data/mon",
		TLS:      TLSConfig{Mode: TLSModeACMEIP},
	})
	t.Setenv(envListen, ":1443")
	t.Setenv(envTLSMode, TLSModeFiles)
	t.Setenv(envTLSCert, "/env/c.pem")
	t.Setenv(envTLSKey, "/env/k.pem")

	cfg, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":1443" {
		t.Fatalf("Listen = %q, want ENV value :1443", cfg.Listen)
	}
	// PublicIP and DataDir were not overridden by ENV, so the file's values
	// must survive the merge.
	if cfg.PublicIP != "203.0.113.10" || cfg.DataDir != "/data/mon" {
		t.Fatalf("Load() = %+v, want file values to survive for unset ENV vars", cfg)
	}
	if cfg.TLS.Mode != TLSModeFiles || cfg.TLS.Cert != "/env/c.pem" || cfg.TLS.Key != "/env/k.pem" {
		t.Fatalf("Load() TLS = %+v, want ENV values", cfg.TLS)
	}
}

// TestLoad_MalformedFile checks that unparsable JSON is a hard error, not a
// silent fall-back to defaults — a broken config file should fail loudly at
// startup, not quietly serve on the wrong port.
func TestLoad_MalformedFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path, true); err == nil {
		t.Fatal("Load() with malformed JSON: want error, got nil")
	}
}

// TestValidate_FilesRequiresCertAndKey checks that "files" mode without a
// full keypair is rejected before the listener ever tries to use it.
func TestValidate_FilesRequiresCertAndKey(t *testing.T) {
	cases := []struct {
		name    string
		tls     TLSConfig
		wantErr bool
	}{
		{"both set", TLSConfig{Mode: TLSModeFiles, Cert: "c", Key: "k"}, false},
		{"missing cert", TLSConfig{Mode: TLSModeFiles, Key: "k"}, true},
		{"missing key", TLSConfig{Mode: TLSModeFiles, Cert: "c"}, true},
		{"missing both", TLSConfig{Mode: TLSModeFiles}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Listen: DefaultListen, DataDir: DefaultDataDir, TLS: tc.tls}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_ACMEIPRequiresPublicIP checks that the default TLS mode
// refuses to proceed without knowing which IP to certify.
func TestValidate_ACMEIPRequiresPublicIP(t *testing.T) {
	cfg := &Config{Listen: DefaultListen, DataDir: DefaultDataDir, TLS: TLSConfig{Mode: TLSModeACMEIP}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() with acme-ip and no publicIp: want error, got nil")
	}

	cfg.PublicIP = "203.0.113.10"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() with acme-ip and publicIp set: %v", err)
	}
}

// TestValidate_ACMEIPRequiresIPLiteral checks that publicIp must actually
// parse as an IP address (net.ParseIP), and that a loopback or private
// address is rejected too: Let's Encrypt can never validate either as
// reachable from the internet, so accepting them would only fail later, at
// ACME time, with a much less obvious error.
func TestValidate_ACMEIPRequiresIPLiteral(t *testing.T) {
	cases := []struct {
		name     string
		publicIP string
		wantErr  bool
	}{
		{"host:port pair", "203.0.113.5:443", true},
		{"hostname", "example.com", true},
		{"loopback", "127.0.0.1", true},
		{"private", "10.0.0.5", true},
		{"ipv4 literal", "203.0.113.5", false},
		{"ipv6 literal", "2001:db8::1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Listen: DefaultListen, DataDir: DefaultDataDir, PublicIP: tc.publicIP, TLS: TLSConfig{Mode: TLSModeACMEIP}}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() with publicIp=%q: error = %v, wantErr %v", tc.publicIP, err, tc.wantErr)
			}
		})
	}
}

// TestValidate_UnknownMode checks that a typo'd tls.mode is rejected rather
// than silently falling through to one of the two known modes.
func TestValidate_UnknownMode(t *testing.T) {
	cfg := &Config{Listen: DefaultListen, DataDir: DefaultDataDir, TLS: TLSConfig{Mode: "bogus"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() with unknown tls.mode: want error, got nil")
	}
}

// TestVersion_DefaultsToDev checks the fallback a binary built without
// -ldflags -X carries, so `mon-server version` never prints an empty string.
func TestVersion_DefaultsToDev(t *testing.T) {
	if Version() != "dev" {
		t.Fatalf("Version() = %q, want %q (unless set via -ldflags in this test binary)", Version(), "dev")
	}
}
