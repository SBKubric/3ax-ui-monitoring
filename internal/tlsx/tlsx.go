// Package tlsx builds the one *tls.Config mon-server's single HTTPS
// listener serves on (spec §2, §2.1). It has exactly two modes: "acme-ip",
// an embedded certmagic instance that gets a Let's Encrypt certificate for
// this box's own public IP address over tls-alpn-01, and "files", an
// operator-supplied cert/key pair for a real domain or for tests that must
// never touch the ACME network.
package tlsx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/caddyserver/certmagic"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
)

// h2AndHTTP1 are the ALPN protocols the listener itself needs, independent
// of TLS mode: gin serves plain HTTP semantics over either HTTP/2 or
// HTTP/1.1, and both must be offered because not every mon-client or admin
// browser negotiates h2.
var h2AndHTTP1 = []string{"h2", "http/1.1"}

// acmeProfile is the ACME profile named by the issue and spec §2.1:
// short-lived certificates (160h validity), which is why the renewal window
// has to be wide (acmeRenewalWindowRatio) rather than the multi-week default
// that suits a normal 90-day Let's Encrypt certificate.
const acmeProfile = "shortlived"

// acmeRenewalWindowRatio ≈ 0.5 (spec §2.1): with a 160h certificate this
// renews roughly every 80h (~3 days), leaving ample margin before expiry
// even if a renewal attempt or two fails.
const acmeRenewalWindowRatio = 0.5

// certsSubdir is where certmagic's FileStorage keeps ACME account data and
// issued certificates under dataDir (spec §2.1: "FileStorage в dataDir/certs").
const certsSubdir = "certs"

// Build returns the *tls.Config for mon-server's single HTTPS listener,
// selected by cfg.Mode (spec §2.1), plus the Manager that owns "acme-ip"
// mode's certmagic lifecycle (nil for "files" mode, which has none). Build
// itself is pure: it never talks to the network. Actually obtaining a
// certificate is the caller's job via Manager.Manage, once the listener is
// bound and there's somewhere to serve a challenge from — see Manager's doc
// comment for why that must not happen inside Build/internal/app.New.
func Build(cfg config.TLSConfig, dataDir, publicIP string) (*tls.Config, *Manager, error) {
	switch cfg.Mode {
	case config.TLSModeFiles:
		tlsCfg, err := buildFiles(cfg, publicIP)
		return tlsCfg, nil, err
	case config.TLSModeACMEIP:
		return buildACMEIP(dataDir, publicIP, ACMEDirectory(cfg.ACMECA))
	default:
		return nil, nil, fmt.Errorf("tlsx: unknown tls.mode %q (want %q or %q)", cfg.Mode, config.TLSModeACMEIP, config.TLSModeFiles)
	}
}

// buildFiles loads an operator-supplied keypair (spec §2.1: "свой cert/key
// (домен или тесты), без ACME"). This is what every test in this repo that
// needs a real TLS listener uses (see tlsxtest.WriteSelfSigned) precisely
// because it never touches the network.
//
// The leaf must carry publicIP as an IP SAN (decision #52 §4): every
// mon-client reaches this listener at probeUrl, https://<publicIp>:<port>,
// so a certificate for a domain only would fail every tunnel probe's TLS
// verification. That is refused here, at start-up, rather than discovered
// as every target going DOWN.
func buildFiles(cfg config.TLSConfig, publicIP string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, fmt.Errorf("tlsx: load keypair (cert=%s, key=%s): %w", cfg.Cert, cfg.Key, err)
	}
	if err := requireIPSAN(cert, publicIP); err != nil {
		return nil, fmt.Errorf("tlsx: %s: %w", cfg.Cert, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   append([]string{}, h2AndHTTP1...),
	}, nil
}

// requireIPSAN checks that the leaf of cert lists publicIP among its IP
// SANs, comparing parsed addresses so "2001:db8::1" matches however the
// certificate happened to encode it.
func requireIPSAN(cert tls.Certificate, publicIP string) error {
	ip := net.ParseIP(publicIP)
	if ip == nil {
		return fmt.Errorf("files mode requires publicIp as an IP address, got %q", publicIP)
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return fmt.Errorf("parse leaf certificate: %w", err)
		}
	}
	for _, san := range leaf.IPAddresses {
		if san.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("cert has no IP SAN for publicIp %s", publicIP)
}

// ACMEDirectory resolves tls.acmeCa (decision #52 §2) to the ACME directory
// URL certmagic needs: "production" or unset is Let's Encrypt production,
// "staging" is Let's Encrypt staging, and anything else is already a
// directory URL (config.Validate has checked its shape). The admin UI shows
// the result on the "TLS & admin" tab.
func ACMEDirectory(ca string) string {
	switch ca {
	case "", config.ACMECAProduction:
		return certmagic.LetsEncryptProductionCA
	case config.ACMECAStaging:
		return certmagic.LetsEncryptStagingCA
	default:
		return ca
	}
}

// buildACMEIP wires up certmagic for the default mode (spec §2.1) and
// returns a Manager the caller must Manage(ctx) once it is safe to do so
// (after the listener is bound). It never calls out to the network itself.
func buildACMEIP(dataDir, publicIP, caDir string) (*tls.Config, *Manager, error) {
	if publicIP == "" {
		return nil, nil, errors.New("tlsx: acme-ip mode requires a public IP")
	}

	magic, cache, _ := acmeSetup(dataDir, publicIP, caDir)

	// magic.TLSConfig() pre-populates NextProtos with certmagic's own
	// acme-tls/1 value (required for tls-alpn-01 to keep working on renewal,
	// not just first issuance) — prepend ours rather than replace it.
	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append(append([]string{}, h2AndHTTP1...), tlsCfg.NextProtos...)
	tlsCfg.MinVersion = tls.VersionTLS12

	mgr := &Manager{
		magic:      magic,
		cache:      cache,
		publicIP:   publicIP,
		manageFunc: defaultManageFunc,
	}
	return tlsCfg, mgr, nil
}

// acmeSetup is the pure, network-free half of acme-ip mode: it builds a
// certmagic.Config, its Cache and its ACMEIssuer with every field the issue
// and spec §2.1 name, and returns all three so a test can assert on their
// fields directly without calling Build. certmagic's own circular
// Config<->Cache wiring (a Cache needs a callback that returns the Config it
// belongs to) is contained here rather than leaking into Build.
//
// DefaultServerName and FallbackServerName are both set to publicIP: an
// IP-literal mon-client (or any TCP client that only ever dials the IP, not
// a hostname) sends no SNI at all in its ClientHello, and on a NAT'd box the
// socket's LocalAddr need not equal the public IP either — without a
// default/fallback name, certmagic has nothing to match the empty or
// mismatched ServerName against and the handshake fails even though the
// right certificate is sitting in the cache.
//
// caDir is the ACME directory (ACMEDirectory of tls.acmeCa). With Let's
// Encrypt production certmagic also retries failed issuances against
// staging first (its implicit TestCA), so retry logs mention the staging
// host even on a production install; staging and custom directories have
// no such second CA. FileStorage keys everything by the CA's host, so
// switching acmeCa never mixes certificates or accounts of different CAs.
func acmeSetup(dataDir, publicIP, caDir string) (*certmagic.Config, *certmagic.Cache, *certmagic.ACMEIssuer) {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
	})

	magic = certmagic.New(cache, certmagic.Config{
		// RenewalWindowRatio ≈ 0.5 (spec §2.1): renew roughly every 80h for
		// a 160h shortlived cert, instead of certmagic's default ratio built
		// for multi-week certificates.
		RenewalWindowRatio: acmeRenewalWindowRatio,
		// FileStorage в dataDir/certs (spec §2.1).
		Storage: &certmagic.FileStorage{Path: filepath.Join(dataDir, certsSubdir)},
		// See the doc comment above: an IP-literal client sends empty SNI,
		// and a NAT'd box's socket LocalAddr may not equal publicIP either,
		// so both the empty-SNI and no-match cases must resolve to the one
		// certificate we manage.
		DefaultServerName:  publicIP,
		FallbackServerName: publicIP,
	})

	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		// tls.acmeCa (decision #52 §2): production by default, staging or
		// a custom directory for stands and e2e.
		CA: caDir,
		// mon-server is a single unattended service with no operator to
		// click "I agree" during a first boot; running it at all implies
		// accepting Let's Encrypt's subscriber agreement.
		Agreed: true,
		// tls-alpn-01 on the same :443 the listener already serves; :80 is
		// never opened (spec §2.1: "DisableHTTPChallenge: true (:80 не
		// нужен)").
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false,
		// shortlived (160h) certificates (spec §2.1).
		Profile: acmeProfile,
	})
	magic.Issuers = []certmagic.Issuer{issuer}

	return magic, cache, issuer
}

// Manager owns "acme-ip" mode's certmagic lifecycle: the *certmagic.Config
// built by acmeSetup, the *certmagic.Cache backing it (whose maintenance
// goroutine must be stopped on shutdown), and the identifier it manages.
// Build returns nil for "files" mode, which has no such lifecycle; every
// method on Manager is nil-safe so callers (internal/app) never need to
// special-case that.
type Manager struct {
	magic      *certmagic.Config
	cache      *certmagic.Cache
	publicIP   string
	manageFunc func(ctx context.Context, magic *certmagic.Config, names []string) error
}

// defaultManageFunc is production's manageFunc: certmagic's asynchronous
// on-demand management. It is a package-level func value, not a method
// closure, purely so tests can construct a Manager with a swapped-in stub
// without touching a package-level var (architecture brief §4: no global
// mutable state).
func defaultManageFunc(ctx context.Context, magic *certmagic.Config, names []string) error {
	return magic.ManageAsync(ctx, names)
}

// Manage asks certmagic to obtain (if not already cached) and keep renewed
// a certificate for this Manager's public IP, asynchronously: it calls
// ManageAsync, not ManageSync, so it returns as soon as the request is
// queued — the listener can start accepting connections immediately instead
// of blocking cold boot on Let's Encrypt, and certmagic retries any failure
// itself with exponential backoff (up to ~30 days). The trade-off this
// accepts deliberately: any TLS handshake that arrives before the first
// issuance completes will fail (no certificate yet to serve). That is
// correct for mon-server — a supervisor that restart-loops a process
// blocked synchronously in New/Build against a possibly-unreachable ACME
// endpoint is worse than a listener that is up and answers /healthz while
// the certificate catches up in the background.
//
// ctx should be a context the caller cancels on shutdown (app.Shutdown
// does): cancelling it stops any in-flight retries and the goroutines
// ManageAsync spawned for them.
func (m *Manager) Manage(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.manageFunc(ctx, m.magic, []string{m.publicIP})
}

// Stop shuts down the certmagic cache's maintenance goroutine. app.Shutdown
// calls this after the HTTP server has finished shutting down, so no test
// run leaks a goroutine under -race.
func (m *Manager) Stop() {
	if m == nil || m.cache == nil {
		return
	}
	m.cache.Stop()
}
