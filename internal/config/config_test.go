package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// envNames is every variable Load reads.
var envNames = []string{EnvListen, EnvPublicIP, EnvDataDir, EnvTLSMode, EnvTLSCert, EnvTLSKey}

// clearEnv removes the MON_* variables for the duration of the test, so the
// environment of the machine running the tests cannot change the outcome.
// t.Setenv registers the restore, os.Unsetenv makes the variable absent rather
// than empty.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range envNames {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}
}

// writeConfig writes body to a config file in a temporary directory and
// returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadDefaultsWhenNothingIsConfigured(t *testing.T) {
	clearEnv(t)

	got, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load with a missing file: %v", err)
	}
	if want := Default(); got != want {
		t.Errorf("Load = %+v, want %+v", got, want)
	}
	if got.Listen != ":443" || got.DataDir != "/var/lib/mon-server" || got.TLS.Mode != TLSModeACMEIP {
		t.Errorf("documented defaults changed: %+v", got)
	}
	if got.PublicIP != "" {
		t.Errorf("publicIp default = %q, want empty", got.PublicIP)
	}
}

func TestLoadFileEnvironmentAndPrecedence(t *testing.T) {
	const file = `{
  "listen": ":8443",
  "publicIp": "203.0.113.10",
  "dataDir": "/srv/mon",
  "tls": {"mode": "files", "cert": "/srv/mon/cert.pem", "key": "/srv/mon/key.pem"}
}`

	tests := []struct {
		name string
		body string // config file body; empty means no file at all
		env  map[string]string
		want Config
	}{
		{
			name: "from the file",
			body: file,
			want: Config{
				Listen:   ":8443",
				PublicIP: "203.0.113.10",
				DataDir:  "/srv/mon",
				TLS:      TLS{Mode: TLSModeFiles, Cert: "/srv/mon/cert.pem", Key: "/srv/mon/key.pem"},
			},
		},
		{
			name: "from the environment alone",
			env: map[string]string{
				EnvListen:   ":9443",
				EnvPublicIP: "198.51.100.7",
				EnvDataDir:  "/data/mon",
				EnvTLSMode:  TLSModeFiles,
				EnvTLSCert:  "/data/cert.pem",
				EnvTLSKey:   "/data/key.pem",
			},
			want: Config{
				Listen:   ":9443",
				PublicIP: "198.51.100.7",
				DataDir:  "/data/mon",
				TLS:      TLS{Mode: TLSModeFiles, Cert: "/data/cert.pem", Key: "/data/key.pem"},
			},
		},
		{
			name: "the environment wins over the file",
			body: file,
			env: map[string]string{
				EnvListen:   ":9443",
				EnvPublicIP: "198.51.100.7",
				EnvTLSMode:  TLSModeACMEIP,
			},
			want: Config{
				Listen:   ":9443",
				PublicIP: "198.51.100.7",
				DataDir:  "/srv/mon",
				TLS:      TLS{Mode: TLSModeACMEIP, Cert: "/srv/mon/cert.pem", Key: "/srv/mon/key.pem"},
			},
		},
		{
			name: "fields the file omits keep their defaults",
			body: `{"publicIp": "203.0.113.10"}`,
			want: Config{
				Listen:   DefaultListen,
				PublicIP: "203.0.113.10",
				DataDir:  DefaultDataDir,
				TLS:      TLS{Mode: DefaultTLSMode},
			},
		},
		{
			name: "blank values fall back to the defaults",
			body: `{"listen": "", "dataDir": "  ", "tls": {"mode": ""}}`,
			env:  map[string]string{EnvPublicIP: "  203.0.113.10  "},
			want: Config{
				Listen:   DefaultListen,
				PublicIP: "203.0.113.10",
				DataDir:  DefaultDataDir,
				TLS:      TLS{Mode: DefaultTLSMode},
			},
		},
		{
			name: "keys the bootstrap file does not know are ignored",
			body: `{"listen": ":7443", "panelUrl": "https://panel.example.net"}`,
			want: Config{Listen: ":7443", DataDir: DefaultDataDir, TLS: TLS{Mode: DefaultTLSMode}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			path := filepath.Join(t.TempDir(), "absent.json")
			if tc.body != "" {
				path = writeConfig(t, tc.body)
			}
			got, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got != tc.want {
				t.Errorf("Load = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLoadReportsABrokenFile(t *testing.T) {
	clearEnv(t)

	path := writeConfig(t, `{"listen": ":8443"`)
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted malformed JSON")
	}
}

func TestLoadUsesTheDefaultPathWhenNoneIsGiven(t *testing.T) {
	clearEnv(t)

	// /etc/mon-server/config.json does not exist in the test environment, so
	// Load falls back to defaults rather than failing.
	if _, err := os.Stat(DefaultPath); err == nil {
		t.Skipf("%s exists on this machine", DefaultPath)
	}
	got, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if want := Default(); got != want {
		t.Errorf("Load(\"\") = %+v, want %+v", got, want)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{
			name: "acme-ip with a public ip",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", PublicIP: "203.0.113.10", TLS: TLS{Mode: TLSModeACMEIP}},
		},
		{
			name: "acme-ip without a public ip",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", TLS: TLS{Mode: TLSModeACMEIP}},
			want: ErrMissingPublicIP,
		},
		{
			name: "files with a certificate and a key",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", TLS: TLS{Mode: TLSModeFiles, Cert: "/c.pem", Key: "/k.pem"}},
		},
		{
			name: "files without a certificate",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", TLS: TLS{Mode: TLSModeFiles, Key: "/k.pem"}},
			want: ErrMissingCertificate,
		},
		{
			name: "files without a key",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", TLS: TLS{Mode: TLSModeFiles, Cert: "/c.pem"}},
			want: ErrMissingCertificate,
		},
		{
			name: "unknown tls mode",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", PublicIP: "203.0.113.10", TLS: TLS{Mode: "self-signed"}},
			want: ErrUnknownTLSMode,
		},
		{
			name: "empty tls mode",
			cfg:  Config{Listen: ":443", DataDir: "/var/lib/mon-server", PublicIP: "203.0.113.10"},
			want: ErrUnknownTLSMode,
		},
		{
			name: "no listen address",
			cfg:  Config{DataDir: "/var/lib/mon-server", PublicIP: "203.0.113.10", TLS: TLS{Mode: TLSModeACMEIP}},
			want: ErrMissingListen,
		},
		{
			name: "no data directory",
			cfg:  Config{Listen: ":443", PublicIP: "203.0.113.10", TLS: TLS{Mode: TLSModeACMEIP}},
			want: ErrMissingDataDir,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsWhatLoadProduces(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvPublicIP, "203.0.113.10")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the default configuration with a public ip does not validate: %v", err)
	}
}

func TestPaths(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/mon-server"}
	if got, want := cfg.DBPath(), "/var/lib/mon-server/mon-server.db"; got != want {
		t.Errorf("DBPath = %q, want %q", got, want)
	}
	if got, want := cfg.CertsDir(), "/var/lib/mon-server/certs"; got != want {
		t.Errorf("CertsDir = %q, want %q", got, want)
	}

	relative := Config{DataDir: "data"}
	if got, want := relative.DBPath(), filepath.Join("data", "mon-server.db"); got != want {
		t.Errorf("DBPath with a relative dataDir = %q, want %q", got, want)
	}
}
