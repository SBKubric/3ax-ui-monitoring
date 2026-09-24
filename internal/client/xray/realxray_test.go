package xray

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// TestRealXrayDetourNamesTheOutbound pins the stderr line Diagnose
// attributes sessions by (decision #53 п. 6) against the real binary: two
// targets whose outbounds dial the same real server are told apart only by
// the dispatcher's `taking detour [<outbound tag>] for [...]` line, written
// under each session's id. If a future xray renamed or dropped that line,
// this is the test that says so — Diagnose would silently fall back to
// addr:port, and two targets on one server would share each other's
// diagnoses again.
func TestRealXrayDetourNamesTheOutbound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in -short mode")
	}
	requireDocker(t)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	portA, portB := freePort(t), freePort(t)
	// 192.0.2.1 is TEST-NET-1: nothing answers there, so each session stays
	// at its dial long enough for the test to read both lines.
	const serverAddr, serverPort = "192.0.2.1", 443
	cfg := fmt.Sprintf(`{
  "log": {"loglevel": "info", "access": "none"},
  "inbounds": [
    {"tag": "in-a", "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"auth": "noauth", "udp": false}},
    {"tag": "in-b", "listen": "127.0.0.1", "port": %d, "protocol": "socks", "settings": {"auth": "noauth", "udp": false}}
  ],
  "outbounds": [
    {"tag": "out-xray-12-proxy", "protocol": "vless", "settings": {"vnext": [{"address": %q, "port": %d,
      "users": [{"id": "6f3a2b1c-8d4e-4f5a-9b6c-7d8e9f0a1b2c", "encryption": "none"}]}]}},
    {"tag": "out-xray-13-proxy", "protocol": "vless", "settings": {"vnext": [{"address": %q, "port": %d,
      "users": [{"id": "6f3a2b1c-8d4e-4f5a-9b6c-7d8e9f0a1b2d", "encryption": "none"}]}]}},
    {"tag": "block", "protocol": "blackhole"}
  ],
  "routing": {"domainStrategy": "AsIs", "rules": [
    {"type": "field", "inboundTag": ["in-a"], "outboundTag": "out-xray-12-proxy"},
    {"type": "field", "inboundTag": ["in-b"], "outboundTag": "out-xray-13-proxy"}]}
}`, portA, portB, serverAddr, serverPort, serverAddr, serverPort)
	if err := os.WriteFile(filepath.Join(dir, "x.json"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p := New(dockerRunWrapper(t, dir), slog.New(slog.NewTextHandler(io.Discard, nil)))
	since := time.Now()
	if err := p.Start(ctxT(t, 2*time.Minute), "/cfg/x.json", []int{portA, portB}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 20*time.Second)) })

	// One socks CONNECT per inbound, to the same destination, the way two
	// probes of one cycle would arrive.
	for _, port := range []int{portA, portB} {
		conn := socksConnect(t, port, net.IPv4(203, 0, 113, 1), 443)
		t.Cleanup(func() { _ = conn.Close() })
	}

	deadline := time.Now().Add(20 * time.Second)
	var snap []Line
	for time.Now().Before(deadline) {
		snap = p.Log().Snapshot()
		if countContaining(snap, detourMarker) >= 2 && countContaining(snap, dialMarker) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, l := range snap {
		t.Logf("xray: %s", l.Text)
	}

	until := time.Now()
	a := targetSessions(snap, Target{OutboundTag: "out-xray-12-proxy", Addr: serverAddr, Port: serverPort}, since, until)
	b := targetSessions(snap, Target{OutboundTag: "out-xray-13-proxy", Addr: serverAddr, Port: serverPort}, since, until)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("sessions: A=%v B=%v, want exactly one each (is `%s<tag>]` still in xray's output?)", a, b, detourMarker)
	}
	for id := range a {
		if b[id] {
			t.Fatalf("both targets were given session %s", id)
		}
	}
}

// socksConnect opens a SOCKS5 CONNECT (no auth) through 127.0.0.1:port to
// ip:dstPort and returns the connection without waiting for the reply —
// the test only needs xray to route and dial, not to succeed.
func socksConnect(t *testing.T, port int, ip net.IP, dstPort int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks %d: %v", port, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("socks greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		t.Fatalf("socks method reply %v: %v", reply, err)
	}
	req := append([]byte{5, 1, 0, 1}, ip.To4()...)
	req = append(req, byte(dstPort>>8), byte(dstPort))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks connect: %v", err)
	}
	return conn
}

// dockerRunWrapper is dockerWrapper for `xray run`: the container shares
// the host's network, so the socks inbounds it binds on 127.0.0.1 are the
// ones Process.Start polls and the test dials. `docker run` forwards the
// SIGTERM Process.Stop sends to the container.
func dockerRunWrapper(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray-docker-run")
	script := "#!/bin/sh\nexec docker run --rm --network host -v " + dir + ":/cfg:ro " + xrayImage + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}
	return path
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
