package tlsx_test

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlstest"
)

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    tlsx.Options
		wantErr string
	}{
		{
			name: "acme-ip is valid",
			opts: tlsx.Options{Mode: tlsx.ModeACMEIP, PublicIP: "203.0.113.5", CertsDir: "/var/lib/mon-server/certs"},
		},
		{
			name: "files is valid",
			opts: tlsx.Options{Mode: tlsx.ModeFiles, CertFile: "/etc/ssl/cert.pem", KeyFile: "/etc/ssl/key.pem"},
		},
		{
			name:    "unknown mode",
			opts:    tlsx.Options{Mode: "self-signed"},
			wantErr: "unknown tls mode",
		},
		{
			name:    "empty mode",
			opts:    tlsx.Options{},
			wantErr: "unknown tls mode",
		},
		{
			name:    "acme-ip without publicIp",
			opts:    tlsx.Options{Mode: tlsx.ModeACMEIP, CertsDir: "/var/lib/mon-server/certs"},
			wantErr: "needs publicIp",
		},
		{
			name:    "acme-ip with a hostname instead of an IP",
			opts:    tlsx.Options{Mode: tlsx.ModeACMEIP, PublicIP: "mon.example.com", CertsDir: "/var/lib/mon-server/certs"},
			wantErr: "to be an IP address",
		},
		{
			name:    "acme-ip without a storage directory",
			opts:    tlsx.Options{Mode: tlsx.ModeACMEIP, PublicIP: "203.0.113.5"},
			wantErr: "certificate storage directory",
		},
		{
			name:    "files without cert",
			opts:    tlsx.Options{Mode: tlsx.ModeFiles, KeyFile: "/etc/ssl/key.pem"},
			wantErr: "needs tls.cert",
		},
		{
			name:    "files without key",
			opts:    tlsx.Options{Mode: tlsx.ModeFiles, CertFile: "/etc/ssl/cert.pem"},
			wantErr: "needs tls.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.opts.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want an error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %q, want it to contain %q", err, tt.wantErr)
			}
			// The same validation must guard both entry points.
			if _, err := tlsx.New(tt.opts); err == nil {
				t.Fatal("New() accepted options Validate rejected")
			}
			if _, err := tlsx.TLSConfig(t.Context(), tt.opts); err == nil {
				t.Fatal("TLSConfig() accepted options Validate rejected")
			}
		})
	}
}

func TestFilesMode(t *testing.T) {
	t.Parallel()

	certFile, keyFile, err := tlstest.WritePair(t.TempDir(), "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("WritePair() = %v", err)
	}

	p, err := tlsx.New(tlsx.Options{Mode: tlsx.ModeFiles, CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.Mode() != tlsx.ModeFiles {
		t.Errorf("Mode() = %q, want %q", p.Mode(), tlsx.ModeFiles)
	}
	if p.ACME() != nil {
		t.Error("ACME() is not nil in files mode")
	}
	cfg := p.TLSConfig()
	if got, want := cfg.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("MinVersion = %#x, want %#x", got, want)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	if cfg.Certificates[0].Leaf == nil {
		t.Error("Certificates[0].Leaf is nil, the parsed leaf is needed for SNI matching")
	}
	// Manage is a no-op in files mode: it must not reach for an ACME server.
	if err := p.Manage(t.Context()); err != nil {
		t.Errorf("Manage() = %v, want nil in files mode", err)
	}
}

func TestFilesModeMissingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile, keyFile, err := tlstest.WritePair(dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("WritePair() = %v", err)
	}
	missing := filepath.Join(dir, "absent.pem")

	tests := map[string]tlsx.Options{
		"missing certificate": {Mode: tlsx.ModeFiles, CertFile: missing, KeyFile: keyFile},
		"missing key":         {Mode: tlsx.ModeFiles, CertFile: certFile, KeyFile: missing},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := tlsx.TLSConfig(t.Context(), opts)
			if err == nil {
				t.Fatal("TLSConfig() = nil error, want a load failure")
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("TLSConfig() = %q, want it to name the unreadable file %q", err, missing)
			}
		})
	}
}

func TestTLSConfigRejectsACMEIP(t *testing.T) {
	t.Parallel()

	_, err := tlsx.TLSConfig(context.Background(), tlsx.Options{
		Mode:     tlsx.ModeACMEIP,
		PublicIP: "203.0.113.5",
		CertsDir: t.TempDir(),
	})
	if !errors.Is(err, tlsx.ErrManageRequired) {
		t.Fatalf("TLSConfig() = %v, want ErrManageRequired: acme-ip needs a Provider that Manage can fill", err)
	}
}
