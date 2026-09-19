// Package config is mon-server's bootstrap layer: the handful of settings a
// process needs before it can even open its database (spec §2). Everything
// else — thresholds, the panel URL, Telegram — lives in the settings table
// (internal/store) and is edited through the admin UI, not here. Keeping the
// bootstrap surface this small is deliberate: it is the only configuration a
// fresh install has to get right before the admin UI exists to fix mistakes.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// version is stamped by the release build via
// -ldflags "-X github.com/SBKubric/3ax-ui-monitoring/internal/config.version=<tag>"
// (spec §11). "dev" marks a binary built without that flag, e.g. every
// local `go build`.
var version = "dev"

// Version returns the build-time version string for `mon-server version` and
// any diagnostic output. It is a function rather than an exported var so
// nothing outside this package can reassign it.
func Version() string { return version }

// Default bootstrap values (spec §2). A fresh install with no config file and
// no MON_* environment gets these; only publicIp has no sane default because
// it names *this* box, so acme-ip mode without it fails Validate below.
const (
	DefaultListen  = ":443"
	DefaultDataDir = "/var/lib/mon-server"
	DefaultTLSMode = "acme-ip"
)

// TLS mode names (spec §2.1). acme-ip is the default: an embedded certmagic
// obtains a Let's Encrypt certificate for the box's own IP. files lets an
// operator supply their own cert/key, e.g. for a real domain or for tests
// that must not touch the ACME network.
const (
	TLSModeACMEIP = "acme-ip"
	TLSModeFiles  = "files"
)

// TLSConfig is the tls.* bootstrap block. Cert and Key are only meaningful
// (and only required, see Validate) when Mode is "files".
type TLSConfig struct {
	Mode string `json:"mode"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// Config is mon-server's whole bootstrap surface (spec §2): where to listen,
// how the outside world reaches this box, where its SQLite file and certs
// live, and how it terminates TLS. Load builds one from defaults, an optional
// JSON file and the environment, in that order of increasing priority.
type Config struct {
	Listen   string    `json:"listen"`
	PublicIP string    `json:"publicIp"`
	DataDir  string    `json:"dataDir"`
	TLS      TLSConfig `json:"tls"`
}

// Environment variable names (spec §2: "или ENV MON_*"). ENV always wins over
// the file so an operator can override one field (e.g. in a systemd unit or a
// container) without templating the whole JSON file.
const (
	envListen   = "MON_LISTEN"
	envPublicIP = "MON_PUBLIC_IP"
	envDataDir  = "MON_DATA_DIR"
	envTLSMode  = "MON_TLS_MODE"
	envTLSCert  = "MON_TLS_CERT"
	envTLSKey   = "MON_TLS_KEY"
)

// defaults returns a Config holding only the built-in defaults, the base
// every Load call starts from.
func defaults() *Config {
	return &Config{
		Listen:  DefaultListen,
		DataDir: DefaultDataDir,
		TLS:     TLSConfig{Mode: DefaultTLSMode},
	}
}

// Load builds the bootstrap config: defaults, overlaid by path if it exists,
// overlaid by MON_* environment variables, which win over both. explicit
// says whether path was named by the caller (e.g. `-config` on the command
// line) rather than being the built-in default: a missing default path is
// not an error — most installs will run on ENV alone, or on defaults plus a
// couple of variables — but a missing path the operator explicitly asked for
// is almost always a typo, and silently falling back to defaults there would
// start the process against the wrong listen address or publicIp without
// any indication why. Load does not validate; call Validate separately once
// you know which fields the caller actually needs (`admin set` does not need
// TLS to be correct, `run` does).
func Load(path string, explicit bool) (*Config, error) {
	cfg := defaults()

	if err := mergeFile(cfg, path, explicit); err != nil {
		return nil, err
	}
	mergeEnv(cfg)

	return cfg, nil
}

// mergeFile overlays the JSON file at path onto cfg. A missing file is
// tolerated only when explicit is false (the caller is falling back to
// defaultConfigPath, not a path it named itself) — the bootstrap config must
// stay usable from ENV alone (e.g. in a container that never mounts
// /etc/mon-server/config.json) without also letting a typo'd `-config` path
// silently start the process on defaults. An unrecognised key in the file
// (DisallowUnknownFields) is always an error, explicit or not: it is either
// a typo'd field name or a value that belongs in the settings table (§9.4)
// instead, and either way silently ignoring it would hide a misconfiguration
// from the operator.
func mergeFile(cfg *Config, path string, explicit bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return nil
		}
		return fmt.Errorf("config: read %s: %w", path, err)
	}

	var file Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}

	if file.Listen != "" {
		cfg.Listen = file.Listen
	}
	if file.PublicIP != "" {
		cfg.PublicIP = file.PublicIP
	}
	if file.DataDir != "" {
		cfg.DataDir = file.DataDir
	}
	if file.TLS.Mode != "" {
		cfg.TLS.Mode = file.TLS.Mode
	}
	if file.TLS.Cert != "" {
		cfg.TLS.Cert = file.TLS.Cert
	}
	if file.TLS.Key != "" {
		cfg.TLS.Key = file.TLS.Key
	}
	return nil
}

// mergeEnv overlays MON_* environment variables onto cfg. It runs after
// mergeFile so ENV always wins (spec §2), field by field: a variable that is
// unset or empty leaves the file/default value alone.
func mergeEnv(cfg *Config) {
	if v, ok := os.LookupEnv(envListen); ok && v != "" {
		cfg.Listen = v
	}
	if v, ok := os.LookupEnv(envPublicIP); ok && v != "" {
		cfg.PublicIP = v
	}
	if v, ok := os.LookupEnv(envDataDir); ok && v != "" {
		cfg.DataDir = v
	}
	if v, ok := os.LookupEnv(envTLSMode); ok && v != "" {
		cfg.TLS.Mode = v
	}
	if v, ok := os.LookupEnv(envTLSCert); ok && v != "" {
		cfg.TLS.Cert = v
	}
	if v, ok := os.LookupEnv(envTLSKey); ok && v != "" {
		cfg.TLS.Key = v
	}
}

// Validate checks that Config is internally consistent enough to start the
// listener (spec §2.1): "files" mode needs both halves of a keypair, and
// "acme-ip" needs to know which IP to certify. It does not check that the
// paths exist or that the IP is reachable — that surfaces naturally when TLS
// setup (step 2) tries to use them.
func (c *Config) Validate() error {
	switch c.TLS.Mode {
	case TLSModeFiles:
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return errors.New("config: tls.mode=files requires tls.cert and tls.key")
		}
	case TLSModeACMEIP:
		if c.PublicIP == "" {
			return errors.New("config: tls.mode=acme-ip requires publicIp")
		}
	default:
		return fmt.Errorf("config: unknown tls.mode %q (want %q or %q)", c.TLS.Mode, TLSModeACMEIP, TLSModeFiles)
	}
	return nil
}
