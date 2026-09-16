package tlsx_test

import (
	"crypto/tls"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/caddyserver/certmagic"

	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
)

// acmeTLS1Protocol is the ALPN protocol of the tls-alpn-01 challenge (RFC
// 8737). It is spelled out rather than taken from certmagic's dependency so
// the test pins the value that goes on the wire.
const acmeTLS1Protocol = "acme-tls/1"

// TestACMEIPConfiguration checks the certmagic wiring of mon-server.md §2.1
// without performing ACME: building a Provider never leaves the process.
func TestACMEIPConfiguration(t *testing.T) {
	t.Parallel()

	certsDir := filepath.Join(t.TempDir(), "certs")
	const publicIP = "203.0.113.5"

	p, err := tlsx.New(tlsx.Options{
		Mode:     tlsx.ModeACMEIP,
		PublicIP: publicIP,
		CertsDir: certsDir,
		Email:    "ops@example.com",
	})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if p.Mode() != tlsx.ModeACMEIP {
		t.Errorf("Mode() = %q, want %q", p.Mode(), tlsx.ModeACMEIP)
	}
	acme := p.ACME()
	if acme == nil {
		t.Fatal("ACME() = nil, want the certmagic wiring in acme-ip mode")
	}

	if acme.Name != publicIP {
		t.Errorf("managed name = %q, want the public IP %q", acme.Name, publicIP)
	}
	if got := acme.Config.RenewalWindowRatio; math.Abs(got-0.5) > 1e-9 {
		t.Errorf("RenewalWindowRatio = %v, want ~0.5 so a 160 h certificate renews every ~3 days", got)
	}
	storage, ok := acme.Config.Storage.(*certmagic.FileStorage)
	if !ok {
		t.Fatalf("Storage = %T, want *certmagic.FileStorage", acme.Config.Storage)
	}
	if storage.Path != certsDir {
		t.Errorf("Storage.Path = %q, want %q", storage.Path, certsDir)
	}

	if acme.Issuer.Profile != tlsx.ACMEProfile {
		t.Errorf("Issuer.Profile = %q, want %q", acme.Issuer.Profile, tlsx.ACMEProfile)
	}
	if tlsx.ACMEProfile != "shortlived" {
		t.Errorf("ACMEProfile = %q, want the 160 h profile %q", tlsx.ACMEProfile, "shortlived")
	}
	if !acme.Issuer.DisableHTTPChallenge {
		t.Error("Issuer.DisableHTTPChallenge = false, want true: :80 is not open")
	}
	if acme.Issuer.DisableTLSALPNChallenge {
		t.Error("Issuer.DisableTLSALPNChallenge = true, want false: it is the only challenge left")
	}
	if acme.Issuer.DNS01Solver != nil {
		t.Error("Issuer.DNS01Solver is set, want nil: mon-server has no DNS provider")
	}
	if acme.Issuer.CA != certmagic.LetsEncryptProductionCA {
		t.Errorf("Issuer.CA = %q, want %q", acme.Issuer.CA, certmagic.LetsEncryptProductionCA)
	}
	if acme.Issuer.Email != "ops@example.com" {
		t.Errorf("Issuer.Email = %q, want the configured account email", acme.Issuer.Email)
	}
	if !acme.Issuer.Agreed {
		t.Error("Issuer.Agreed = false, want true: an ACME account cannot be created otherwise")
	}
	if len(acme.Config.Issuers) != 1 || acme.Config.Issuers[0] != certmagic.Issuer(acme.Issuer) {
		t.Errorf("Config.Issuers = %v, want exactly the ACME issuer that is exposed", acme.Config.Issuers)
	}

	// Building the Provider must not have touched the ACME account storage.
	if _, err := os.Stat(certsDir); !os.IsNotExist(err) {
		t.Errorf("os.Stat(%q) = %v, want the storage directory to stay untouched until Manage runs", certsDir, err)
	}
}

func TestACMEIPTLSConfig(t *testing.T) {
	t.Parallel()

	p, err := tlsx.New(tlsx.Options{
		Mode:     tlsx.ModeACMEIP,
		PublicIP: "203.0.113.5",
		CertsDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	cfg := p.TLSConfig()
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate is nil, certmagic must answer handshakes")
	}
	if !slices.Contains(cfg.NextProtos, acmeTLS1Protocol) {
		t.Errorf("NextProtos = %v, want it to advertise %q so tls-alpn-01 is solved on the same listener", cfg.NextProtos, acmeTLS1Protocol)
	}
	if got, want := cfg.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Errorf("MinVersion = %#x, want %#x", got, want)
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("Certificates = %v, want none: certificates come from the certmagic cache", cfg.Certificates)
	}
}

// TestACMEIPEmptyEmail covers the optional ACME account email.
func TestACMEIPEmptyEmail(t *testing.T) {
	t.Parallel()

	p, err := tlsx.New(tlsx.Options{
		Mode:     tlsx.ModeACMEIP,
		PublicIP: "2001:db8::5",
		CertsDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New() = %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	if got := p.ACME().Issuer.Email; got != "" {
		t.Errorf("Issuer.Email = %q, want it empty when no email is configured", got)
	}
	if got := p.ACME().Name; got != "2001:db8::5" {
		t.Errorf("managed name = %q, want the IPv6 address unchanged", got)
	}
}
