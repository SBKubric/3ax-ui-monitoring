// Package tlsx builds the TLS configuration of mon-server's single HTTPS
// listener (mon-server.md §2.1, mon-protocol.md §1). Two modes:
//
//   - ModeACMEIP (production default): certmagic obtains a Let's Encrypt
//     certificate for the box's public IP address (RFC 8738) with the
//     "shortlived" ACME profile, solving the tls-alpn-01 challenge on the very
//     listener this configuration serves, so no :80 is needed. Renewal runs at
//     half the certificate lifetime, i.e. about every three days.
//   - ModeFiles: an operator-supplied certificate and key (a domain
//     deployment, e2e, local runs). No ACME at all.
//
// The package does not import internal/config on purpose: the wiring layer
// maps the bootstrap config onto Options, and tests build Options directly.
//
// Nothing in this package reaches the network except [Provider.Manage].
package tlsx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

// Mode selects where the listener's certificate comes from. The values are the
// ones the bootstrap config accepts for tls.mode.
type Mode string

const (
	// ModeACMEIP issues a Let's Encrypt certificate for a public IP address.
	ModeACMEIP Mode = "acme-ip"
	// ModeFiles serves a certificate and key from disk.
	ModeFiles Mode = "files"
)

// Options is the self-contained input of this package; the wiring layer fills
// it from the bootstrap config.
type Options struct {
	// Mode is ModeACMEIP or ModeFiles. There is no default: the bootstrap
	// config layer is the one that knows acme-ip is the spec default.
	Mode Mode
	// PublicIP is the address the certificate is issued for (acme-ip only).
	PublicIP string
	// CertsDir is the certmagic FileStorage root, dataDir/certs (acme-ip only).
	CertsDir string
	// CertFile is the PEM certificate chain (files mode).
	CertFile string
	// KeyFile is the PEM private key matching CertFile (files mode).
	KeyFile string
	// Email is an optional ACME account contact; may be empty.
	Email string
	// Log receives certificate lifecycle events. May be nil.
	Log *slog.Logger
}

// Validate reports whether the options describe a usable mode.
func (o Options) Validate() error {
	switch o.Mode {
	case ModeACMEIP:
		if o.PublicIP == "" {
			return fmt.Errorf("tlsx: mode %q needs publicIp, the IP the certificate is issued for", o.Mode)
		}
		if net.ParseIP(o.PublicIP) == nil {
			return fmt.Errorf("tlsx: mode %q needs publicIp to be an IP address, got %q", o.Mode, o.PublicIP)
		}
		if o.CertsDir == "" {
			return fmt.Errorf("tlsx: mode %q needs a certificate storage directory", o.Mode)
		}
		return nil
	case ModeFiles:
		if o.CertFile == "" {
			return fmt.Errorf("tlsx: mode %q needs tls.cert, the certificate file", o.Mode)
		}
		if o.KeyFile == "" {
			return fmt.Errorf("tlsx: mode %q needs tls.key, the private key file", o.Mode)
		}
		return nil
	default:
		return fmt.Errorf("tlsx: unknown tls mode %q, want %q or %q", o.Mode, ModeACMEIP, ModeFiles)
	}
}

// Provider owns the TLS state of one listener: the configuration the listener
// hands to crypto/tls and, in acme-ip mode, the certmagic cache that the same
// configuration serves handshakes from.
//
// Building a Provider never touches the network. In acme-ip mode the
// certificate is obtained and kept fresh by Manage, which must run against the
// same Provider that serves the handshakes, because the certificate lives in
// that Provider's in-memory cache.
type Provider struct {
	mode Mode
	log  *slog.Logger
	tls  *tls.Config
	acme *ACME
}

// New validates the options and builds the Provider. It performs no network
// I/O: in files mode it reads the key pair from disk, in acme-ip mode it only
// assembles the certmagic wiring.
//
// The caller owns the Provider and should Close it when the listener is gone.
//
// Typical wiring:
//
//	p, err := tlsx.New(opts)
//	defer p.Close()
//	srv, err := server.New(server.Options{TLSConfig: p.TLSConfig(), ...})
//	go srv.Serve(ctx)
//	err = p.Manage(ctx) // ACME runs over the listener that is already up
func New(o Options) (*Provider, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	p := &Provider{mode: o.Mode, log: log}
	switch o.Mode {
	case ModeFiles:
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: load key pair (cert %q, key %q): %w", o.CertFile, o.KeyFile, err)
		}
		p.tls = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
	case ModeACMEIP:
		p.acme = newACME(o, log)
		p.tls = p.acme.tlsConfig()
	}
	return p, nil
}

// TLSConfig is the configuration the listener serves with. In acme-ip mode its
// NextProtos carries the ACME TLS-ALPN protocol, so the challenge is answered
// on the same port; the listener is expected to append h2 and http/1.1 (which
// is what net/http's Server.ServeTLS does).
func (p *Provider) TLSConfig() *tls.Config { return p.tls }

// Mode reports which mode the Provider was built for.
func (p *Provider) Mode() Mode { return p.mode }

// ACME exposes the certmagic wiring, or nil in files mode. It exists so the
// wiring layer can log what was configured and tests can assert on it without
// performing ACME.
func (p *Provider) ACME() *ACME { return p.acme }

// Manage obtains the certificate and keeps it renewed. It is a no-op in files
// mode. In acme-ip mode it blocks until the certificate is loaded from storage
// or issued by the CA, so it must be called after the listener is accepting
// connections: the tls-alpn-01 challenge is answered by that same listener.
// Afterwards renewal happens in the background until Close.
func (p *Provider) Manage(ctx context.Context) error {
	if p.acme == nil {
		return nil
	}
	p.log.Info("obtaining certificate", "ip", p.acme.Name, "profile", ACMEProfile)
	if err := p.acme.Config.ManageSync(ctx, []string{p.acme.Name}); err != nil {
		return fmt.Errorf("tlsx: manage certificate for %s: %w", p.acme.Name, err)
	}
	return nil
}

// Close stops background certificate maintenance. It is safe to call once.
func (p *Provider) Close() error {
	if p.acme != nil {
		p.acme.close()
	}
	return nil
}

// ErrManageRequired is returned by TLSConfig for acme-ip options: that mode
// needs a live Provider, because the certificate Manage obtains is served out
// of the Provider's own certificate cache.
var ErrManageRequired = errors.New("tlsx: acme-ip needs tlsx.New plus Provider.Manage, not the one-shot TLSConfig")

// TLSConfig is the one-shot form for callers that never manage certificates:
// files mode, tests and e2e. ctx is accepted for symmetry with
// [Provider.Manage]; nothing here blocks on it.
//
// It deliberately refuses acme-ip rather than handing back a configuration
// nobody will ever put a certificate into.
func TLSConfig(ctx context.Context, o Options) (*tls.Config, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if o.Mode != ModeFiles {
		return nil, fmt.Errorf("%w (mode %q)", ErrManageRequired, o.Mode)
	}
	p, err := New(o)
	if err != nil {
		return nil, err
	}
	return p.TLSConfig(), nil
}
