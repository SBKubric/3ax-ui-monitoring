package panel_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// otherCertPEM is a certificate unrelated to every TLS stub's: httptest
// serves all of them with the same built-in certificate, so a second stub
// would not do.
func otherCertPEM(t *testing.T) string {
	t.Helper()
	certPath, _ := tlsxtest.WriteSelfSigned(t, t.TempDir())
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	return string(raw)
}

// TestParseCA checks the panelCa setting's accepted shapes (decision #52
// §1): empty means "use the system pool" (a nil pool, no error), one or
// more PEM certificates make a pool, and anything that is not purely PEM
// certificates — garbage, a private key pasted by mistake, a truncated
// block — is refused so Save and Check can say so instead of the poller
// silently trusting nothing.
func TestParseCA(t *testing.T) {
	cert := paneltest.NewTLSStub(t).CertPEM()
	other := otherCertPEM(t)

	cases := []struct {
		name     string
		pem      string
		wantPool bool
		wantErr  bool
	}{
		{"empty", "", false, false},
		{"whitespace", " \n\t", false, false},
		{"one certificate", cert, true, false},
		{"chain of two", cert + other, true, false},
		{"surrounding whitespace", "\n  " + cert + "\n", true, false},
		{"garbage", "not a certificate", false, true},
		{"certificate then garbage", cert + "trailing junk", false, true},
		{"private key", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----\n", false, true},
		{"truncated", cert[:len(cert)/2], false, true},
		{"bad DER", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := panel.ParseCA(tc.pem)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseCA() error = %v, wantErr %v", err, tc.wantErr)
			}
			if (pool != nil) != tc.wantPool {
				t.Fatalf("ParseCA() pool = %v, want non-nil %v", pool, tc.wantPool)
			}
		})
	}
}

// TestHTTPClient_UnknownAuthorityWithoutPanelCA checks the failure panelCa
// exists for: a panel on a certificate no system CA knows fails the TLS
// handshake, and IsUnknownAuthority recognises that error through every
// wrapper (url.Error, the client's own netError, tls.CertificateVerification
// Error) so Check and the status line can name it (decision #52 §1).
func TestHTTPClient_UnknownAuthorityWithoutPanelCA(t *testing.T) {
	s := paneltest.NewTLSStub(t)
	c, sleeps := newClient(t, s)

	_, err := c.State(context.Background())
	if err == nil {
		t.Fatal("State against an untrusted certificate: want error, got nil")
	}
	if !panel.IsUnknownAuthority(err) {
		t.Fatalf("IsUnknownAuthority(%v) = false, want true", err)
	}
	// Retrying cannot change the certificate: the answer comes at once
	// (the Check button would otherwise sit through 1+2+4 s of backoff),
	// while the error stays retryable for the stats flush — the panel is
	// unreachable, not rejecting the batch.
	wantDelays(t, sleeps.delays())
	if !panel.IsRetryable(err) {
		t.Fatal("IsRetryable(unknown authority) = false, want true (keep the batch)")
	}
}

// TestHTTPClient_PanelCATrustsSelfSignedPanel checks the fix: with the
// panel's own (self-signed) certificate as the only root, the same request
// succeeds.
func TestHTTPClient_PanelCATrustsSelfSignedPanel(t *testing.T) {
	s := paneltest.NewTLSStub(t)
	pool, err := panel.ParseCA(s.CertPEM())
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	c, _ := newClient(t, s, panel.WithRootCAs(pool))

	if _, err := c.State(context.Background()); err != nil {
		t.Fatalf("State with panelCa set to the panel's certificate: %v", err)
	}
}

// TestHTTPClient_PanelCAReplacesSystemPool checks that panelCa replaces the
// trust store rather than adding to it: a pool holding some other
// certificate does not trust this panel.
func TestHTTPClient_PanelCAReplacesSystemPool(t *testing.T) {
	s := paneltest.NewTLSStub(t)
	pool, err := panel.ParseCA(otherCertPEM(t))
	if err != nil {
		t.Fatalf("ParseCA: %v", err)
	}
	c, _ := newClient(t, s, panel.WithRootCAs(pool))

	_, err = c.State(context.Background())
	if !panel.IsUnknownAuthority(err) {
		t.Fatalf("State with an unrelated panelCa: err = %v, want an unknown-authority error", err)
	}
}

// TestIsUnknownAuthority_OtherErrors checks that the predicate does not
// fire for the failures that already have their own messages.
func TestIsUnknownAuthority_OtherErrors(t *testing.T) {
	for _, err := range []error{nil, panel.ErrNotFound, panel.ErrBadBody, &panel.APIError{Status: 500}} {
		if panel.IsUnknownAuthority(err) {
			t.Errorf("IsUnknownAuthority(%v) = true, want false", err)
		}
	}
	if strings.Contains(panel.ErrNotFound.Error(), "x509") {
		t.Fatal("sanity: ErrNotFound should not mention x509")
	}
}
