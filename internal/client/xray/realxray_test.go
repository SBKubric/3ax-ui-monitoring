package xray

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// xrayImage is the official image the spec pins mon-client's binary to
// (brief §1: ghcr.io/xtls/xray-core:latest = Xray 26.3.27, research §2.2).
const xrayImage = "ghcr.io/xtls/xray-core:latest"

// TestRealXrayTest runs Process.Test against the real xray binary in its
// official image: the fake in testdata reproduces the contract (exit 23 plus
// an error line, "Configuration OK." otherwise, research §2.2) and this test
// is what proves the contract is real. It skips when docker is unavailable,
// so `go test ./...` on a laptop stays green; CI runs it with the image
// pulled (brief §1).
func TestRealXrayTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in -short mode")
	}
	requireDocker(t)

	dir := t.TempDir()
	// The image is distroless/nonroot: the mounted config must be readable
	// by a user that is not us.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("good.json", goodConfig)
	write("bad.json", badConfig)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := New(dockerWrapper(t, dir), logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := p.Test(ctx, "/cfg/good.json"); err != nil {
		t.Errorf("Test(good) = %v, want nil", err)
	}
	err := p.Test(ctx, "/cfg/bad.json")
	if err == nil {
		t.Fatalf("Test(bad) = nil, want an error")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Errorf("Test(bad) returned an empty message")
	}
	if len([]rune(err.Error())) > maxDetail {
		t.Errorf("Test(bad) message is %d runes, want ≤ %d", len([]rune(err.Error())), maxDetail)
	}
	t.Logf("real xray rejected the config with: %s", err)

	v, err := p.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v == "" || strings.EqualFold(v, "xray") {
		t.Errorf("Version = %q, want a version number", v)
	}
	t.Logf("real xray version: %s", v)
}

// requireDocker skips the test unless a working docker daemon is reachable.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		t.Skipf("docker unavailable: %v: %s", err, out)
	}
}

// dockerWrapper returns a path that behaves like the xray binary but runs it
// in the official image with dir mounted at /cfg, so Process can be exercised
// unchanged against the real thing.
func dockerWrapper(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray-docker")
	script := "#!/bin/sh\nexec docker run --rm -v " + dir + ":/cfg:ro " + xrayImage + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	return path
}

// goodConfig is the minimal one-target config of research §2.1.
const goodConfig = `{
  "log": {"loglevel": "info", "access": "none"},
  "inbounds": [
    {"tag": "in-xray-12-proxy", "listen": "127.0.0.1", "port": 10801, "protocol": "socks",
     "settings": {"auth": "noauth", "udp": false}}
  ],
  "outbounds": [
    {"tag": "out-xray-12-proxy", "protocol": "vless",
     "settings": {"vnext": [{"address": "203.0.113.10", "port": 443,
       "users": [{"id": "6f3a2b1c-8d4e-4f5a-9b6c-7d8e9f0a1b2c", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"serverName": "www.cloudflare.com", "fingerprint": "chrome",
         "publicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "shortId": "0123456789abcdef",
         "spiderX": "/", "show": false}}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs",
    "rules": [{"type": "field", "inboundTag": ["in-xray-12-proxy"], "outboundTag": "out-xray-12-proxy"}]}
}`

// badConfig is goodConfig without the mandatory "encryption":"none" on the
// vless user (research §2.1), the error mon-client is most likely to make
// when a share link omits it.
const badConfig = `{
  "log": {"loglevel": "info", "access": "none"},
  "inbounds": [
    {"tag": "in-xray-12-proxy", "listen": "127.0.0.1", "port": 10801, "protocol": "socks",
     "settings": {"auth": "noauth", "udp": false}}
  ],
  "outbounds": [
    {"tag": "out-xray-12-proxy", "protocol": "vless",
     "settings": {"vnext": [{"address": "203.0.113.10", "port": 443,
       "users": [{"id": "6f3a2b1c-8d4e-4f5a-9b6c-7d8e9f0a1b2c"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
       "realitySettings": {"serverName": "www.cloudflare.com", "fingerprint": "chrome",
         "publicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "shortId": "0123456789abcdef"}}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs",
    "rules": [{"type": "field", "inboundTag": ["in-xray-12-proxy"], "outboundTag": "out-xray-12-proxy"}]}
}`
