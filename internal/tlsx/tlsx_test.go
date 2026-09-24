package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// errBoom is a sentinel error for tests that only care that Manage
// propagates a failure from its manageFunc, not what the failure was.
var errBoom = errors.New("boom")

// TestBuild_Files_LoadsKeypair checks that "files" mode (spec §2.1) loads the
// operator-supplied cert/key straight off disk and sets the baseline every
// mon-server listener needs: TLS 1.2 minimum and ALPN protocols for both
// HTTP/2 and HTTP/1.1 so gin can negotiate either, and that Build reports no
// Manager for this mode (there is no certmagic lifecycle to own).
func TestBuild_Files_LoadsKeypair(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)

	tlsCfg, mgr, err := Build(config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath}, dir, "127.0.0.1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if mgr != nil {
		t.Fatalf("Manager = %v, want nil for files mode", mgr)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2", tlsCfg.MinVersion)
	}
	if !containsAll(tlsCfg.NextProtos, "h2", "http/1.1") {
		t.Fatalf("NextProtos = %v, want it to include h2 and http/1.1", tlsCfg.NextProtos)
	}

	// A nil Manager must be safe to use exactly like app.go uses it, with no
	// special-casing at the call site.
	if err := mgr.Manage(context.Background()); err != nil {
		t.Fatalf("nil Manager.Manage: %v", err)
	}
	mgr.Stop()
}

// TestBuild_Files_MissingKeypairFails checks that a bad cert/key path is a
// hard error from Build, not a listener that silently starts with no TLS
// certificate and fails on the first handshake instead.
func TestBuild_Files_MissingKeypairFails(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Build(config.TLSConfig{Mode: config.TLSModeFiles, Cert: filepath.Join(dir, "missing.pem"), Key: filepath.Join(dir, "missing-key.pem")}, dir, "127.0.0.1")
	if err == nil {
		t.Fatal("Build with a missing keypair: want error, got nil")
	}
}

// TestBuild_Files_RequiresIPSANForPublicIP checks decision #52 §4: probeUrl
// is always https://<publicIp>:<port>/v1/probe, so a "files" certificate that
// does not carry publicIp as an IP SAN would fail every mon-client's TLS
// verification. Build refuses to start with one instead — both for a
// domain-only certificate and for one issued for some other IP.
func TestBuild_Files_RequiresIPSANForPublicIP(t *testing.T) {
	cases := []struct {
		name     string
		dns      []string
		ips      []net.IP
		publicIP string
		wantErr  bool
	}{
		{"matching IPv4 SAN", nil, []net.IP{net.ParseIP("203.0.113.10")}, "203.0.113.10", false},
		{"matching IPv6 SAN", nil, []net.IP{net.ParseIP("2001:db8::1")}, "2001:db8::1", false},
		{"domain only", []string{"mon.example.com"}, nil, "203.0.113.10", true},
		{"other IP", []string{"mon.example.com"}, []net.IP{net.ParseIP("203.0.113.11")}, "203.0.113.10", true},
		{"empty publicIp", nil, []net.IP{net.ParseIP("203.0.113.10")}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := tlsxtest.WriteCert(t, dir, tc.dns, tc.ips)
			_, _, err := Build(config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath}, dir, tc.publicIP)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Build() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && tc.publicIP != "" && !strings.Contains(err.Error(), "cert has no IP SAN for publicIp") {
				t.Fatalf("Build() error = %q, want it to say %q", err, "cert has no IP SAN for publicIp")
			}
		})
	}
}

// TestACMEDirectory checks the tls.acmeCa names (decision #52 §2):
// production (and an unset value) is Let's Encrypt's production directory,
// staging its staging directory, and anything else is taken as a directory
// URL verbatim — Pebble in e2e/CI.
func TestACMEDirectory(t *testing.T) {
	cases := map[string]string{
		"":                         certmagic.LetsEncryptProductionCA,
		config.ACMECAProduction:    certmagic.LetsEncryptProductionCA,
		config.ACMECAStaging:       certmagic.LetsEncryptStagingCA,
		"https://pebble:14000/dir": "https://pebble:14000/dir",
	}
	for in, want := range cases {
		if got := ACMEDirectory(in); got != want {
			t.Errorf("ACMEDirectory(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuild_ACMEIP_UsesConfiguredCA checks that tls.acmeCa reaches the
// certmagic issuer: an ansible stand run with acmeCa=staging must never
// spend a production issuance.
func TestBuild_ACMEIP_UsesConfiguredCA(t *testing.T) {
	_, mgr, err := Build(config.TLSConfig{Mode: config.TLSModeACMEIP, ACMECA: config.ACMECAStaging}, t.TempDir(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(mgr.Stop)

	if len(mgr.magic.Issuers) != 1 {
		t.Fatalf("Issuers = %v, want exactly one", mgr.magic.Issuers)
	}
	issuer, ok := mgr.magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		t.Fatalf("Issuers[0] = %T, want *certmagic.ACMEIssuer", mgr.magic.Issuers[0])
	}
	if issuer.CA != certmagic.LetsEncryptStagingCA {
		t.Fatalf("CA = %q, want the Let's Encrypt staging directory", issuer.CA)
	}
}

// TestBuild_UnknownMode checks that an unrecognised tls.mode is a named
// error instead of silently falling through to one of the two known modes.
func TestBuild_UnknownMode(t *testing.T) {
	_, _, err := Build(config.TLSConfig{Mode: "bogus"}, t.TempDir(), "203.0.113.10")
	if err == nil {
		t.Fatal("Build with tls.mode=bogus: want error, got nil")
	}
}

// TestAcmeSetup_ConfiguresExpectedFields checks the certmagic wiring the
// issue names exactly: shortlived profile, HTTP challenge disabled (only
// tls-alpn-01 on :443), the renewal window ratio for a 160h cert, on-disk
// storage under dataDir/certs, and DefaultServerName/FallbackServerName both
// set to publicIP so an IP-literal client's empty-SNI handshake still
// selects the cached cert. It calls the pure constructor directly so it
// never touches the network.
func TestAcmeSetup_ConfiguresExpectedFields(t *testing.T) {
	dataDir := t.TempDir()
	magic, cache, issuer := acmeSetup(dataDir, "203.0.113.10", ACMEDirectory(""))
	t.Cleanup(cache.Stop)

	if magic.RenewalWindowRatio != acmeRenewalWindowRatio {
		t.Fatalf("RenewalWindowRatio = %v, want %v", magic.RenewalWindowRatio, acmeRenewalWindowRatio)
	}
	fs, ok := magic.Storage.(*certmagic.FileStorage)
	if !ok {
		t.Fatalf("Storage = %T, want *certmagic.FileStorage", magic.Storage)
	}
	wantPath := filepath.Join(dataDir, "certs")
	if fs.Path != wantPath {
		t.Fatalf("Storage.Path = %q, want %q", fs.Path, wantPath)
	}
	if magic.DefaultServerName != "203.0.113.10" {
		t.Fatalf("DefaultServerName = %q, want %q", magic.DefaultServerName, "203.0.113.10")
	}
	if magic.FallbackServerName != "203.0.113.10" {
		t.Fatalf("FallbackServerName = %q, want %q", magic.FallbackServerName, "203.0.113.10")
	}

	if issuer.Profile != acmeProfile {
		t.Fatalf("Profile = %q, want %q", issuer.Profile, acmeProfile)
	}
	if !issuer.DisableHTTPChallenge {
		t.Fatal("DisableHTTPChallenge = false, want true (only tls-alpn-01 on :443)")
	}
	if issuer.DisableTLSALPNChallenge {
		t.Fatal("DisableTLSALPNChallenge = true, want false (this is the only challenge we use)")
	}
	if issuer.CA != certmagic.LetsEncryptProductionCA {
		t.Fatalf("CA = %q, want the Let's Encrypt production directory", issuer.CA)
	}

	if len(magic.Issuers) != 1 || magic.Issuers[0] != issuer {
		t.Fatalf("Issuers = %v, want exactly [issuer]", magic.Issuers)
	}
}

// TestBuild_ACMEIP_ReturnsManagerForPublicIPOnly checks that Build wires the
// certmagic config for exactly the box's own public IP and returns a
// Manager without ever calling out to the network — Manage is the caller's
// job, done later, not Build's.
func TestBuild_ACMEIP_ReturnsManagerForPublicIPOnly(t *testing.T) {
	tlsCfg, mgr, err := Build(config.TLSConfig{Mode: config.TLSModeACMEIP}, t.TempDir(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(mgr.Stop)

	if mgr == nil {
		t.Fatal("Manager = nil, want a non-nil Manager for acme-ip mode")
	}
	if mgr.publicIP != "203.0.113.10" {
		t.Fatalf("Manager.publicIP = %q, want %q", mgr.publicIP, "203.0.113.10")
	}
	if !containsAll(tlsCfg.NextProtos, "h2", "http/1.1", "acme-tls/1") {
		t.Fatalf("NextProtos = %v, want h2, http/1.1 and acme-tls/1", tlsCfg.NextProtos)
	}
}

// TestManager_Manage_CallsManageFuncWithPublicIPOnly checks that Manage
// invokes the swappable manageFunc with exactly the box's own public IP —
// this test swaps manageFunc for a recorder on the Manager value (not a
// package-level var) so no real ACME call ever happens.
func TestManager_Manage_CallsManageFuncWithPublicIPOnly(t *testing.T) {
	_, mgr, err := Build(config.TLSConfig{Mode: config.TLSModeACMEIP}, t.TempDir(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(mgr.Stop)

	var gotNames []string
	mgr.manageFunc = func(_ context.Context, _ *certmagic.Config, names []string) error {
		gotNames = names
		return nil
	}

	if err := mgr.Manage(context.Background()); err != nil {
		t.Fatalf("Manage: %v", err)
	}
	if len(gotNames) != 1 || gotNames[0] != "203.0.113.10" {
		t.Fatalf("manageFunc called with %v, want [203.0.113.10]", gotNames)
	}
}

// TestManager_Manage_PropagatesFailure checks that a failure from manageFunc
// (in production: ManageAsync failing before it even queues ACME
// transactions) surfaces as an error from Manage.
func TestManager_Manage_PropagatesFailure(t *testing.T) {
	_, mgr, err := Build(config.TLSConfig{Mode: config.TLSModeACMEIP}, t.TempDir(), "203.0.113.10")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(mgr.Stop)

	mgr.manageFunc = func(context.Context, *certmagic.Config, []string) error { return errBoom }

	if err := mgr.Manage(context.Background()); err == nil {
		t.Fatal("Manage with a failing manageFunc: want error, got nil")
	}
}

// TestBuild_ACMEIP_RequiresPublicIP checks Build's own defensive check: even
// though config.Validate() already refuses acme-ip without a publicIp, Build
// must not silently manage an empty identifier if ever called directly.
func TestBuild_ACMEIP_RequiresPublicIP(t *testing.T) {
	if _, _, err := Build(config.TLSConfig{Mode: config.TLSModeACMEIP}, t.TempDir(), ""); err == nil {
		t.Fatal("Build with acme-ip and empty publicIP: want error, got nil")
	}
}

// TestManager_NilIsSafe checks that every Manager method tolerates a nil
// receiver, since Build returns nil for "files" mode and internal/app must
// be able to call Manage/Stop unconditionally regardless of TLS mode.
func TestManager_NilIsSafe(t *testing.T) {
	var mgr *Manager
	if err := mgr.Manage(context.Background()); err != nil {
		t.Fatalf("nil Manager.Manage: %v", err)
	}
	mgr.Stop() // must not panic
}

func containsAll(hay []string, needles ...string) bool {
	for _, n := range needles {
		found := false
		for _, h := range hay {
			if h == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
