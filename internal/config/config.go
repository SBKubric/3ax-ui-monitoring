// Package config loads the mon-server bootstrap configuration (spec
// mon-server.md §2): the handful of settings that must be known before the
// database exists. Everything else lives in the settings table and is edited
// through the admin UI (§9.4).
//
// Values come from three layers, later layers winning over earlier ones:
//
//  1. built-in defaults (Default),
//  2. the JSON file at DefaultPath or the path given to Load,
//  3. MON_* environment variables.
//
// A missing configuration file is not an error: defaults plus environment are
// a complete configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPath is where mon-server looks for its bootstrap file when no other
// path is given.
const DefaultPath = "/etc/mon-server/config.json"

// TLS modes accepted by Config.TLS.Mode (spec §2.1).
const (
	// TLSModeACMEIP obtains a short-lived Let's Encrypt certificate for the
	// public IP through certmagic, over tls-alpn-01 on the same listener.
	TLSModeACMEIP = "acme-ip"
	// TLSModeFiles serves an operator-supplied certificate and key.
	TLSModeFiles = "files"
)

// Defaults for the bootstrap fields (spec §2).
const (
	DefaultListen  = ":443"
	DefaultDataDir = "/var/lib/mon-server"
	DefaultTLSMode = TLSModeACMEIP
)

// Environment variables read by Load. An environment variable that is set
// overrides the file; an empty value falls back to the default.
const (
	EnvListen   = "MON_LISTEN"
	EnvPublicIP = "MON_PUBLIC_IP"
	EnvDataDir  = "MON_DATA_DIR"
	EnvTLSMode  = "MON_TLS_MODE"
	EnvTLSCert  = "MON_TLS_CERT"
	EnvTLSKey   = "MON_TLS_KEY"
)

// Validation failures, wrapped by Validate so callers can test for a cause.
var (
	// ErrUnknownTLSMode reports a tls.mode that is neither acme-ip nor files.
	ErrUnknownTLSMode = errors.New("unknown tls mode")
	// ErrMissingCertificate reports tls.mode=files without cert and key.
	ErrMissingCertificate = errors.New("tls certificate and key are required")
	// ErrMissingPublicIP reports tls.mode=acme-ip without publicIp: ACME for
	// an IP address cannot be requested without knowing the address.
	ErrMissingPublicIP = errors.New("publicIp is required")
	// ErrMissingListen reports an empty listen address.
	ErrMissingListen = errors.New("listen is required")
	// ErrMissingDataDir reports an empty data directory.
	ErrMissingDataDir = errors.New("dataDir is required")
)

// TLS is the tls section of the bootstrap file.
type TLS struct {
	// Mode is TLSModeACMEIP (default) or TLSModeFiles.
	Mode string `json:"mode"`
	// Cert is the PEM certificate chain, used when Mode is TLSModeFiles.
	Cert string `json:"cert"`
	// Key is the PEM private key, used when Mode is TLSModeFiles.
	Key string `json:"key"`
}

// Config is the bootstrap configuration of a mon-server process.
type Config struct {
	// Listen is the address of the single HTTPS listener, e.g. ":443".
	Listen string `json:"listen"`
	// PublicIP is the address mon-clients reach and the identity ACME issues
	// the certificate for. It also forms probeUrl (spec §5).
	PublicIP string `json:"publicIp"`
	// DataDir holds the SQLite database and the certificate storage.
	DataDir string `json:"dataDir"`
	// TLS selects how the listener obtains its certificate.
	TLS TLS `json:"tls"`
}

// Default returns the configuration used when neither file nor environment
// says otherwise.
func Default() Config {
	return Config{
		Listen:  DefaultListen,
		DataDir: DefaultDataDir,
		TLS:     TLS{Mode: DefaultTLSMode},
	}
}

// Load reads the bootstrap configuration from path (DefaultPath when path is
// empty) and then applies the MON_* environment variables over it. A missing
// file is not an error. Load does not validate; call Validate.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath
	}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// Defaults plus environment are a complete configuration.
	default:
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg.applyEnv(os.LookupEnv)
	return cfg.normalized(), nil
}

// applyEnv overlays the MON_* variables. lookup has the signature of
// os.LookupEnv so tests can supply their own environment.
func (c *Config) applyEnv(lookup func(string) (string, bool)) {
	for _, e := range []struct {
		name  string
		field *string
	}{
		{EnvListen, &c.Listen},
		{EnvPublicIP, &c.PublicIP},
		{EnvDataDir, &c.DataDir},
		{EnvTLSMode, &c.TLS.Mode},
		{EnvTLSCert, &c.TLS.Cert},
		{EnvTLSKey, &c.TLS.Key},
	} {
		if v, ok := lookup(e.name); ok {
			*e.field = v
		}
	}
}

// normalized trims the string fields and restores the default of every field
// left blank, so that an empty file value or an empty environment variable
// behaves like an absent one.
func (c Config) normalized() Config {
	c.Listen = strings.TrimSpace(c.Listen)
	c.PublicIP = strings.TrimSpace(c.PublicIP)
	c.DataDir = strings.TrimSpace(c.DataDir)
	c.TLS.Mode = strings.TrimSpace(c.TLS.Mode)
	c.TLS.Cert = strings.TrimSpace(c.TLS.Cert)
	c.TLS.Key = strings.TrimSpace(c.TLS.Key)

	def := Default()
	if c.Listen == "" {
		c.Listen = def.Listen
	}
	if c.DataDir == "" {
		c.DataDir = def.DataDir
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = def.TLS.Mode
	}
	return c
}

// Validate reports whether the configuration can start a listener.
func (c Config) Validate() error {
	if c.Listen == "" {
		return ErrMissingListen
	}
	if c.DataDir == "" {
		return ErrMissingDataDir
	}
	switch c.TLS.Mode {
	case TLSModeACMEIP:
		if c.PublicIP == "" {
			return fmt.Errorf("tls.mode=%s: %w", TLSModeACMEIP, ErrMissingPublicIP)
		}
	case TLSModeFiles:
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return fmt.Errorf("tls.mode=%s: %w", TLSModeFiles, ErrMissingCertificate)
		}
	default:
		return fmt.Errorf("tls.mode=%q: %w (want %q or %q)", c.TLS.Mode, ErrUnknownTLSMode, TLSModeACMEIP, TLSModeFiles)
	}
	return nil
}

// DBPath is the single SQLite file of the process (spec §3).
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "mon-server.db") }

// CertsDir is the certmagic FileStorage directory (spec §2.1).
func (c Config) CertsDir() string { return filepath.Join(c.DataDir, "certs") }
