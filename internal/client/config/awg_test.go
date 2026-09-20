package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readConf(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "awg3.conf"))
	if err != nil {
		t.Fatalf("read testdata/awg3.conf: %v", err)
	}
	return string(raw)
}

// TestParseAWGConfGolden pins the UAPI translation of an AmneziaWG 3.x `.conf`
// (research §3.4): lowercase keys, base64 keys turned into hex, Address and
// MTU taken out for netstack, DNS and PersistentKeepalive dropped.
func TestParseAWGConfGolden(t *testing.T) {
	cfg, err := ParseAWGConf(readConf(t))
	if err != nil {
		t.Fatalf("ParseAWGConf: %v", err)
	}
	golden(t, "awg3.uapi", []byte(cfg.UAPI))

	if got, want := len(cfg.LocalAddresses), 2; got != want {
		t.Fatalf("LocalAddresses = %d, want %d", got, want)
	}
	if got := cfg.LocalAddresses[0].String(); got != "10.66.66.2" {
		t.Errorf("LocalAddresses[0] = %s, want 10.66.66.2 (prefix length dropped)", got)
	}
	if got := cfg.LocalAddresses[1].String(); got != "fd42:42:42::2" {
		t.Errorf("LocalAddresses[1] = %s, want fd42:42:42::2", got)
	}
	if cfg.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", cfg.MTU)
	}
	if cfg.Endpoint != "198.51.100.50:51820" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
	if strings.Contains(cfg.UAPI, "persistent_keepalive") {
		t.Error("UAPI keeps persistent_keepalive_interval; it must be dropped (spec §4 step 2)")
	}
	if strings.Contains(strings.ToLower(cfg.UAPI), "dns") {
		t.Error("UAPI keeps DNS; it must be ignored (spec §4 step 2)")
	}
	// device.IpcSet needs the interface keys before any peer key, and
	// private_key first of all (research §3.4).
	if !strings.HasPrefix(cfg.UAPI, "private_key=") {
		t.Error("UAPI does not start with private_key")
	}
	if strings.Index(cfg.UAPI, "public_key=") < strings.Index(cfg.UAPI, "jc=") {
		t.Error("UAPI has a peer key before the interface keys")
	}
}

// TestParseAWGConfMTUDefault: a `.conf` without MTU means 1420 (spec §4 step 2).
func TestParseAWGConfMTUDefault(t *testing.T) {
	conf := removeLine(readConf(t), "MTU")
	cfg, err := ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v", err)
	}
	if cfg.MTU != DefaultMTU {
		t.Errorf("MTU = %d, want the default %d", cfg.MTU, DefaultMTU)
	}
}

// TestParseAWGConfErrors: a broken `.conf` fails with the field named, so the
// run loop can put it on the wire as `configError` (spec §4 step 3).
func TestParseAWGConfErrors(t *testing.T) {
	full := readConf(t)
	cases := []struct {
		name string
		conf string
		want string
	}{
		{"no PrivateKey", removeLine(full, "PrivateKey"), "PrivateKey"},
		{"no Address", removeLine(full, "Address"), "Address"},
		{"no PublicKey", removeLine(full, "PublicKey"), "PublicKey"},
		{"no peer", strings.Split(full, "[Peer]")[0], "[Peer]"},
		{"no interface", "[Peer]\nPublicKey = KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkc=\n", "[Interface]"},
		{"key is not base64", strings.Replace(full, "PrivateKey = AQ", "PrivateKey = !!", 1), "base64"},
		{"key is too short", strings.Replace(full,
			"PrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
			"PrivateKey = AQIDBAUGBwgJCgsM", 1), "32"},
		{"bad MTU", strings.Replace(full, "MTU = 1420", "MTU = huge", 1), "MTU"},
		{"bad Address", strings.Replace(full, "Address = 10.66.66.2/32", "Address = not-an-ip", 1), "Address"},
		{"bad AllowedIPs", strings.Replace(full, "AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0", 1), "AllowedIPs"},
		{"bad Endpoint", strings.Replace(full, "Endpoint = 198.51.100.50:51820", "Endpoint = 198.51.100.50", 1), "Endpoint"},
		{"unknown interface key", strings.Replace(full, "Jc = 4", "Jx = 4", 1), "Jx"},
		{"unknown peer key", strings.Replace(full, "PersistentKeepalive = 25", "Whatever = 25", 1), "Whatever"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAWGConf(tc.conf)
			if err == nil {
				t.Fatal("ParseAWGConf = nil error, want one")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
			if len(err.Error()) > 256 {
				t.Errorf("error is %d characters, longer than the configError limit of 256", len(err.Error()))
			}
		})
	}
}

// removeLine drops every line whose key is prefix (used to build broken confs).
func removeLine(conf, prefix string) string {
	var kept []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}
