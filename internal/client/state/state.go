// Package state owns mon-client's on-disk state directory (spec §2):
// state.json, which is what makes a box "already registered", and the path
// helper the buffer (cycles.json, step 7) and config applier (xray.json,
// step 8) use to find their own files in the same directory.
//
// state.json holds a secret (the client token), so every write is 0600 and
// every read of the directory itself is confined to 0700 — a mon-client
// runs as an unprivileged process with no capabilities (spec §1), and the
// state directory is the only place on disk that matters for its security.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// stateFileName is state.json's name within the state directory (spec §2).
const stateFileName = "state.json"

// dirMode and fileMode are spec §2's file permissions: 0700 on the
// directory (nothing but this process should even be able to list what is
// in there) and 0600 on state.json (the client token inside it must not be
// world- or group-readable).
const (
	dirMode  = 0o700
	fileMode = 0o600
)

// ErrNoState is Load's answer when state.json does not exist — spec §2:
// "Пока его нет — регистрация". It is not an error a caller logs and gives
// up on; it is the normal first-boot condition and the trigger for §3's
// registration flow.
var ErrNoState = errors.New("state: no state file")

// File is state.json's content (spec §2, issue #15): everything mon-client
// needs to skip registration and pick up where the last run left off.
// AppliedRevision is here rather than only ever recomputed, because it is
// what makes "config unchanged, nothing to do" a fact recoverable
// across a restart instead of forcing a GET /v1/config every single boot.
type File struct {
	MonClientID     string `json:"monClientId"`
	Token           string `json:"token"`
	ServerURL       string `json:"serverUrl"`
	AppliedRevision string `json:"appliedRevision"`
}

// Dir is an opened state directory: the one handle every other package in
// mon-client goes through to read or write anything durable. Holding just
// the path (rather than, say, open file descriptors) is deliberate — the
// directory outlives the process, and each operation opens exactly the
// file it needs for exactly as long as it needs it.
type Dir struct {
	path string
}

// Open ensures path exists as a directory (creating it, and any missing
// parents, at dirMode if it does not) and returns a Dir over it. It does
// not touch state.json itself — Open succeeding says nothing about whether
// a mon-client is already registered, only that its state directory is
// usable; call Load for that.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(path, dirMode); err != nil {
		return nil, fmt.Errorf("state: open %s: %w", path, err)
	}
	return &Dir{path: path}, nil
}

// Path joins name onto the state directory — how cycles.json (step 7) and
// xray.json (step 8) find their place next to state.json without this
// package needing to know anything about either file's content.
func (d *Dir) Path(name string) string {
	return filepath.Join(d.path, name)
}

// Load reads and decodes state.json. A missing file is ErrNoState, spec
// §2's "not registered yet" — every other error (unreadable file, invalid
// JSON) is returned as-is: the spec's rule for a corrupt file ("стереть и
// регистрироваться заново") is the caller's decision to make, not this
// package's, since only the caller knows whether "corrupt" and "absent"
// should really be handled identically.
func (d *Dir) Load() (*File, error) {
	raw, err := os.ReadFile(d.Path(stateFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoState
		}
		return nil, fmt.Errorf("state: read state.json: %w", err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("state: decode state.json: %w", err)
	}
	return &f, nil
}

// Save writes f to state.json atomically: encode to a temp file in the
// same directory (so the final rename is on the same filesystem and
// therefore atomic), fsync it, then rename over state.json. A crash or
// power loss between those steps leaves either the old file intact or the
// new one fully written — never a half-written state.json with a truncated
// token in it. The temp file is created at fileMode directly (rather than
// chmod'd after the fact) so there is no window, however short, where the
// token sits in a file the surrounding umask made group- or
// world-readable.
func (d *Dir) Save(f *File) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("state: encode state.json: %w", err)
	}

	tmp, err := os.CreateTemp(d.path, stateFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("state: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Any failure past this point must not leave the temp file behind.
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("state: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, d.Path(stateFileName)); err != nil {
		return fmt.Errorf("state: rename into place: %w", err)
	}
	success = true
	return nil
}

// Clear removes state.json only — cycles.json and xray.json are left in
// place. Protocol §2.3, §5.3: a 401 (token revoked) or a corrupt state
// file means "forget the registration and start over", not "forget every
// working file mon-client has ever written".
func (d *Dir) Clear() error {
	if err := os.Remove(d.Path(stateFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("state: remove state.json: %w", err)
	}
	return nil
}
