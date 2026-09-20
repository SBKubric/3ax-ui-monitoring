package tlsx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// TestInspectCert_Files: "files" mode reads the operator's own certificate
// and reports its window, with no renewal schedule of mon-server's own.
func TestInspectCert_Files(t *testing.T) {
	dir := t.TempDir()
	cert, key := tlsxtest.WriteSelfSigned(t, dir)

	info, err := InspectCert(config.TLSConfig{Mode: config.TLSModeFiles, Cert: cert, Key: key}, dir)
	if err != nil {
		t.Fatalf("InspectCert: %v", err)
	}
	if info == nil {
		t.Fatal("InspectCert returned no info for an existing certificate")
	}
	if info.NotAfter.Before(info.NotBefore) {
		t.Fatalf("NotAfter %v is before NotBefore %v", info.NotAfter, info.NotBefore)
	}
	if !info.RenewAt.IsZero() {
		t.Fatalf("RenewAt = %v, want zero in files mode", info.RenewAt)
	}
	if info.Subject != "127.0.0.1" {
		t.Fatalf("Subject = %q, want the certificate's first IP SAN", info.Subject)
	}
}

// TestInspectCert_ACMENotIssuedYet: a fresh acme-ip install has no
// certificate on disk yet, which the admin UI shows as "not issued", not as
// an error.
func TestInspectCert_ACMENotIssuedYet(t *testing.T) {
	info, err := InspectCert(config.TLSConfig{Mode: config.TLSModeACMEIP}, t.TempDir())
	if err != nil {
		t.Fatalf("InspectCert: %v", err)
	}
	if info != nil {
		t.Fatalf("InspectCert = %+v, want nil for a store with no certificate", info)
	}
}

// TestInspectCert_ACMEFromStorage: once certmagic has written a certificate
// into dataDir/certs, InspectCert finds it by its storage layout and
// predicts the renewal (spec §2.1's acmeRenewalWindowRatio).
func TestInspectCert_ACMEFromStorage(t *testing.T) {
	dataDir := t.TempDir()
	src, _ := tlsxtest.WriteSelfSigned(t, t.TempDir())
	pem, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source certificate: %v", err)
	}

	dir := filepath.Join(dataDir, certsSubdir, "certificates", "acme-v02.api.letsencrypt.org-directory", "192.0.2.44")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "192.0.2.44.crt"), pem, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}

	info, err := InspectCert(config.TLSConfig{Mode: config.TLSModeACMEIP}, dataDir)
	if err != nil {
		t.Fatalf("InspectCert: %v", err)
	}
	if info == nil {
		t.Fatal("InspectCert found no certificate in certmagic's storage layout")
	}
	lifetime := info.NotAfter.Sub(info.NotBefore)
	want := info.NotAfter.Add(-time.Duration(acmeRenewalWindowRatio * float64(lifetime)))
	if !info.RenewAt.Equal(want) {
		t.Fatalf("RenewAt = %v, want %v", info.RenewAt, want)
	}
}

// TestInspectCert_Garbage: a file that exists but is not a certificate is an
// error an operator must see, not a silent "no certificate".
func TestInspectCert_Garbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := InspectCert(config.TLSConfig{Mode: config.TLSModeFiles, Cert: path, Key: path}, dir); err == nil {
		t.Fatal("InspectCert on a non-certificate file: want an error, got nil")
	}
}
