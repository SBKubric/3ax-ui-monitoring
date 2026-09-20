package tlsx

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
)

// CertInfo is what the admin UI's read-only "TLS & admin" tab shows about
// the certificate this process is serving (spec §9.4: "срок сертификата и
// следующее продление"). It is deliberately a snapshot of the certificate on
// disk rather than of the live tls.Config: the admin UI only ever reads it,
// and reaching into certmagic's cache would mean holding a Manager the UI
// has no other use for.
type CertInfo struct {
	// Subject is the name (or IP) the certificate was issued for.
	Subject string
	// NotBefore/NotAfter are the certificate's validity window.
	NotBefore, NotAfter time.Time
	// RenewAt is when certmagic will try to renew in "acme-ip" mode
	// (acmeRenewalWindowRatio of the lifetime before expiry, spec §2.1).
	// It is the zero time in "files" mode, where renewal is the operator's
	// business and mon-server has no schedule to show.
	RenewAt time.Time
}

// InspectCert reads the certificate mon-server serves and reports its
// validity window for the admin UI (spec §9.4). It returns (nil, nil) when
// there is no certificate yet — the normal state of a freshly booted
// "acme-ip" install whose first issuance has not completed — because "not
// yet" is something the UI shows, not an error it reports. A malformed or
// unreadable certificate that does exist is an error: that one an operator
// needs to see.
func InspectCert(cfg config.TLSConfig, dataDir string) (*CertInfo, error) {
	switch cfg.Mode {
	case config.TLSModeFiles:
		return inspectFile(cfg.Cert, false)
	case config.TLSModeACMEIP:
		path, err := newestACMECert(dataDir)
		if err != nil || path == "" {
			return nil, err
		}
		return inspectFile(path, true)
	default:
		return nil, fmt.Errorf("tlsx: unknown tls.mode %q", cfg.Mode)
	}
}

// newestACMECert finds the certificate certmagic last wrote under
// dataDir/certs (certsSubdir), whose FileStorage layout is
// certificates/<issuer>/<name>/<name>.crt. An install that has renewed
// through more than one issuer (a staging directory, then production) can
// hold several; the most recently modified one is the one being served.
// No match is ("", nil): issuance simply has not happened yet.
func newestACMECert(dataDir string) (string, error) {
	pattern := filepath.Join(dataDir, certsSubdir, "certificates", "*", "*", "*.crt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("tlsx: scan %s: %w", pattern, err)
	}

	var newest string
	var newestMod time.Time
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if newest == "" || fi.ModTime().After(newestMod) {
			newest, newestMod = m, fi.ModTime()
		}
	}
	return newest, nil
}

// inspectFile parses the first certificate in a PEM file — the leaf, by
// convention in both certmagic's storage and any sane operator-supplied
// bundle — and fills in RenewAt when acme says the renewal schedule is
// mon-server's to predict.
func inspectFile(path string, acme bool) (*CertInfo, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("tlsx: read certificate %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("tlsx: %s does not start with a PEM CERTIFICATE block", path)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse certificate %s: %w", path, err)
	}

	info := &CertInfo{
		Subject:   certName(crt),
		NotBefore: crt.NotBefore.UTC(),
		NotAfter:  crt.NotAfter.UTC(),
	}
	if acme {
		lifetime := info.NotAfter.Sub(info.NotBefore)
		info.RenewAt = info.NotAfter.Add(-time.Duration(acmeRenewalWindowRatio * float64(lifetime)))
	}
	return info, nil
}

// certName picks the most useful name to show: the first IP SAN (what
// "acme-ip" mode issues for), else the first DNS SAN, else the subject's
// common name.
func certName(crt *x509.Certificate) string {
	if len(crt.IPAddresses) > 0 {
		return crt.IPAddresses[0].String()
	}
	if len(crt.DNSNames) > 0 {
		return crt.DNSNames[0]
	}
	return crt.Subject.CommonName
}
