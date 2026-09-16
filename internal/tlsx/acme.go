package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync/atomic"

	"github.com/caddyserver/certmagic"
)

const (
	// ACMEProfile is the ACME profile mon-server asks the CA for: 160-hour
	// certificates (mon-server.md §2.1). Profiles are draft-aaron-acme-profiles;
	// Let's Encrypt publishes the supported names in its directory.
	ACMEProfile = "shortlived"

	// RenewalWindowRatio is the share of a certificate's lifetime that is the
	// renewal window, counted from its end. Half of 160 hours puts the first
	// renewal attempt about three days after issuance.
	RenewalWindowRatio = 0.5
)

// ACME is the certmagic wiring built for ModeACMEIP. It is exported so the
// wiring layer can log it and tests can assert on it; obtaining a certificate
// happens only in [Provider.Manage].
type ACME struct {
	// Config is the certmagic configuration backing the listener.
	Config *certmagic.Config
	// Issuer is the Let's Encrypt ACME issuer Config issues through.
	Issuer *certmagic.ACMEIssuer
	// Name is the managed identifier: the public IP of this mon-server.
	Name string

	cache *certmagic.Cache
}

// newACME assembles the certmagic Config, its certificate cache and the ACME
// issuer. Nothing here talks to the network.
func newACME(o Options, log *slog.Logger) *ACME {
	// The cache needs a Config to maintain certificates with, and the Config
	// needs the cache: certmagic resolves the cycle with this callback, so the
	// Config is published through a pointer the callback reads at use time.
	var current atomic.Pointer[certmagic.Config]
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			if cfg := current.Load(); cfg != nil {
				return cfg, nil
			}
			return nil, errors.New("tlsx: certificate cache used before its config was built")
		},
	})

	cfg := certmagic.New(cache, certmagic.Config{
		// Half the lifetime, so a 160 h certificate is renewed every ~3 days.
		RenewalWindowRatio: RenewalWindowRatio,
		// dataDir/certs, so certificates survive restarts and upgrades.
		Storage: &certmagic.FileStorage{Path: o.CertsDir},
		OnEvent: eventLogger(log),
	})
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:      certmagic.LetsEncryptProductionCA,
		Email:   o.Email,
		Agreed:  true,
		Profile: ACMEProfile,
		// Only tls-alpn-01 on the listener itself: :80 stays closed and no DNS
		// provider is involved (mon-server.md §2.1).
		DisableHTTPChallenge: true,
	})
	cfg.Issuers = []certmagic.Issuer{issuer}
	current.Store(cfg)

	return &ACME{Config: cfg, Issuer: issuer, Name: o.PublicIP, cache: cache}
}

// tlsConfig returns the listener configuration: certmagic answers handshakes,
// including the tls-alpn-01 challenge advertised through NextProtos.
func (a *ACME) tlsConfig() *tls.Config {
	cfg := a.Config.TLSConfig() // GetCertificate plus the acme-tls/1 protocol
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// close stops the cache's background maintenance goroutine.
func (a *ACME) close() { a.cache.Stop() }

// eventLogger bridges certmagic's certificate lifecycle events into slog.
// certmagic's own logger is a zap logger and cannot be pointed at slog without
// taking zap as a direct dependency, so the events carry the useful part.
func eventLogger(log *slog.Logger) func(context.Context, string, map[string]any) error {
	return func(ctx context.Context, event string, data map[string]any) error {
		level := slog.LevelInfo
		switch event {
		case "tls_get_certificate":
			// One per TLS handshake; far too noisy to log.
			return nil
		case "cert_failed":
			level = slog.LevelError
		}
		attrs := make([]any, 0, 2*len(data))
		for _, k := range slices.Sorted(maps.Keys(data)) {
			attrs = append(attrs, k, data[k])
		}
		log.Log(ctx, level, "certmagic "+event, attrs...)
		return nil
	}
}
