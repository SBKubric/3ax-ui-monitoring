package config

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// xrayImage is the official image, the tag the brief pins for every test that
// needs a real xray (research §2.2).
const xrayImage = "ghcr.io/xtls/xray-core:latest"

// TestIntegrationXrayAcceptsGeneratedConfig feeds generated configs to the real
// `xray -test`, the same check spec §4 step 3 runs before every restart: if the
// core rejects what this package generates, mon-client would sit on the old
// revision forever with a configError.
//
// It uses the `xray` binary when there is one and the official image otherwise,
// and skips when neither is available; CI runs it with the image.
func TestIntegrationXrayAcceptsGeneratedConfig(t *testing.T) {
	cases := []struct {
		name    string
		targets []proto.Target
	}{
		// The two-target golden: what a mon-client with one inbound and
		// both paths actually runs.
		{"two targets", twoTargets(t)},
		// One target per supported protocol, so every branch of ParseLink
		// is validated by the core and not only by a golden.
		{"every protocol", []proto.Target{
			{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 1, Path: "proxy"}, Protocol: "vless", Link: vlessRealityLink},
			{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 2, Path: "proxy"}, Protocol: "vless", Link: vlessTLSWSLink},
			{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 3, Path: "proxy"}, Protocol: "trojan", Link: trojanGRPCLink},
			{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 4, Path: "proxy"}, Protocol: "shadowsocks", Link: ssLink},
			{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 5, Path: "proxy"}, Protocol: "vmess", Link: vmessLink()},
		}},
		// A mon-client whose config has no xray-targets still writes a
		// config file, and the core has to accept it (spec §4 step 4).
		{"no targets", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := BuildXray(tc.targets, FirstSocksPort)
			if err != nil {
				t.Fatalf("BuildXray: %v", err)
			}
			runXrayTest(t, cfg)
		})
	}
}

// runXrayTest writes cfg to a temp file and runs `xray -test -c` on it.
func runXrayTest(t *testing.T, cfg []byte) {
	t.Helper()

	dir := t.TempDir()
	// The image runs as a non-root user, so the bind mount and its parent
	// have to be readable by it.
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}
	path := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(path, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	switch {
	case hasXrayBinary():
		cmd = exec.CommandContext(ctx, "xray", "-test", "-c", path)
	case hasXrayImage(ctx, t):
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none",
			"-v", dir+":/cfg:ro", xrayImage, "-test", "-c", "/cfg/xray.json")
	default:
		t.Skipf("neither an `xray` binary on PATH nor docker with %s is available; "+
			"run `docker pull %s` to enable this test", xrayImage, xrayImage)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(cmd.Args, " "), err, out)
	}
	if !strings.Contains(string(out), "Configuration OK") {
		t.Errorf("xray -test did not report Configuration OK:\n%s", out)
	}
}

func hasXrayBinary() bool {
	_, err := exec.LookPath("xray")
	return err == nil
}

// hasXrayImage reports whether docker can run the image, pulling it once when
// it is not in the local store yet.
func hasXrayImage(ctx context.Context, t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", xrayImage).Run(); err == nil {
		return true
	}
	t.Logf("pulling %s", xrayImage)
	out, err := exec.CommandContext(ctx, "docker", "pull", xrayImage).CombinedOutput()
	if err != nil {
		t.Logf("docker pull %s failed: %v\n%s", xrayImage, err, out)
		return false
	}
	return true
}
