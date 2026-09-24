package panel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

// ParseCA turns the panelCa setting (decision #52 §1, spec §9.4) into the
// root pool panel requests trust. An empty (or all-whitespace) value is
// (nil, nil): no panelCa, use the system pool. Anything else must be one or
// more PEM CERTIFICATE blocks and nothing else — a stray private key, a
// truncated paste or trailing text is an error, because a pool that
// silently dropped the part it could not read would fail later, and far
// less legibly, as "unknown authority". A self-signed panel leaf is a valid
// entry: Go accepts a root pool that holds the leaf itself.
func ParseCA(pemText string) (*x509.CertPool, error) {
	rest := bytes.TrimSpace([]byte(pemText))
	if len(rest) == 0 {
		return nil, nil
	}

	pool := x509.NewCertPool()
	for n := 1; len(rest) > 0; n++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("panelCa: block %d is not PEM", n)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("panelCa: block %d is %q, want CERTIFICATE", n, block.Type)
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("panelCa: block %d: %w", n, err)
		}
		pool.AddCert(crt)
		rest = bytes.TrimSpace(rest)
	}
	return pool, nil
}

// WithRootCAs makes the client trust exactly pool for the panel's TLS
// certificate — the panelCa setting, which replaces the system pool rather
// than adding to it (decision #52 §1). A nil pool leaves the default
// transport, and with it the system pool, in place.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *HTTPClient) {
		if pool == nil {
			return
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		c.hc.Transport = tr
	}
}

// IsUnknownAuthority reports whether err is the panel's TLS certificate
// failing verification for want of a trusted root — x509's "certificate
// signed by unknown authority". It gets its own text in Check and in the
// Settings status line (decision #52 §1), because the cure is specific:
// paste the panel's certificate into panelCa.
//
// crypto/tls wraps it as *tls.CertificateVerificationError, net/http as
// *url.Error and this package as *netError; all three unwrap, so errors.As
// reaches the x509 value underneath.
func IsUnknownAuthority(err error) bool {
	var ua x509.UnknownAuthorityError
	return errors.As(err, &ua)
}
