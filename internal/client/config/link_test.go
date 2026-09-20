package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Sample links in the exact shapes the panel's sub/subService.go generates
// (genVlessLink, genTrojanLink, genShadowsocksLink, buildVmessLink). They carry
// documentation addresses and throwaway keys only.
const (
	vlessRealityLink = "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@198.51.100.10:443" +
		"?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality" +
		"&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" +
		"&sid=6ba85179e30d4fc2&fp=chrome&spx=%2FKmSmLBwPvOvfmd#ams-1-proxy"

	vlessTLSWSLink = "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@front.example.com:8443" +
		"?type=ws&encryption=none&security=tls&sni=front.example.com&fp=firefox" +
		"&path=%2Fprobe&host=front.example.com&alpn=h2%2Chttp%2F1.1#ams-1-direct"

	trojanGRPCLink = "trojan://s3cr3t-p4ssw0rd@198.51.100.20:443" +
		"?type=grpc&security=tls&sni=trojan.example.org&serviceName=probesvc&mode=multi#ams-2"

	// SIP002: base64("aes-256-gcm:hunter2hunter2") as the userinfo.
	ssLink = "ss://YWVzLTI1Ni1nY206aHVudGVyMmh1bnRlcjI=@198.51.100.30:8388?type=tcp#ams-3"

	// The payload of the vmess:// link; the link itself is base64 of this.
	vmessJSON = `{"v":"2","ps":"ams-4","add":"198.51.100.40","port":"2053","id":"9f0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8",` +
		`"aid":"0","scy":"auto","net":"ws","type":"none","host":"vmess.example.net","path":"/vm","tls":"tls","sni":"vmess.example.net","fp":"chrome"}`
)

// vmessLink is the panel's buildVmessLink: "vmess://" + base64(JSON).
func vmessLink() string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
}

// TestParseLinkGolden pins the outbound JSON of one link per protocol against
// testdata, so a change in the mapping table (research §2.1) is visible in the
// diff rather than only in `xray -test`.
func TestParseLinkGolden(t *testing.T) {
	cases := []struct {
		name     string
		link     string
		golden   string
		wantAddr string
		wantPort int
	}{
		{"vless reality raw", vlessRealityLink, "outbound-vless-reality.json", "198.51.100.10", 443},
		{"vless tls ws", vlessTLSWSLink, "outbound-vless-tls-ws.json", "front.example.com", 8443},
		{"trojan tls grpc", trojanGRPCLink, "outbound-trojan-grpc.json", "198.51.100.20", 443},
		{"shadowsocks sip002", ssLink, "outbound-shadowsocks.json", "198.51.100.30", 8388},
		{"vmess ws tls", vmessLink(), "outbound-vmess-ws.json", "198.51.100.40", 2053},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, addr, port, err := ParseLink(tc.link)
			if err != nil {
				t.Fatalf("ParseLink: %v", err)
			}
			if addr != tc.wantAddr || port != tc.wantPort {
				t.Errorf("addr/port = %s:%d, want %s:%d", addr, port, tc.wantAddr, tc.wantPort)
			}
			goldenJSON(t, tc.golden, out)
		})
	}
}

// TestParseLinkRawEqualsTCP: `type=raw` is the new spelling of `type=tcp` and
// the core folds them together (research §2.1), so both must produce the same
// outbound — otherwise the goldens would drift with the panel's spelling.
func TestParseLinkRawEqualsTCP(t *testing.T) {
	rawLink := strings.Replace(vlessRealityLink, "type=tcp", "type=raw", 1)
	withTCP, _, _, err := ParseLink(vlessRealityLink)
	if err != nil {
		t.Fatalf("tcp: %v", err)
	}
	withRaw, _, _, err := ParseLink(rawLink)
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	gotTCP := withTCP["streamSettings"].(map[string]any)["network"]
	gotRaw := withRaw["streamSettings"].(map[string]any)["network"]
	if gotTCP != "tcp" || gotRaw != "tcp" {
		t.Errorf("network: tcp link = %v, raw link = %v, want both \"tcp\"", gotTCP, gotRaw)
	}
}

// TestParseLinkRealityPQV: the post-quantum verification key of a Reality link
// lands in `mldsa65Verify` (research §2.1). It is kept out of the golden links
// because the core validates it as a real 1952-byte ML-DSA-65 key, which the
// integration test would (rightly) reject.
func TestParseLinkRealityPQV(t *testing.T) {
	// The parameter goes before the #fragment, the way the panel builds it.
	link := strings.Replace(vlessRealityLink, "#", "&pqv=c29tZS1tbGRzYTY1LWtleQ#", 1)
	out, _, _, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	reality := out["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if got := reality["mldsa65Verify"]; got != "c29tZS1tbGRzYTY1LWtleQ" {
		t.Errorf("mldsa65Verify = %v, want the pqv value", got)
	}
}

// TestParseLinkDefaults covers the defaults of research §2.1: a vless link
// without `encryption` means "none", and a Reality link without `spx` means
// "/".
func TestParseLinkDefaults(t *testing.T) {
	link := "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@198.51.100.10:443" +
		"?security=reality&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	out, _, _, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	users := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)
	if got := users[0].(map[string]any)["encryption"]; got != "none" {
		t.Errorf("encryption = %v, want \"none\"", got)
	}
	reality := out["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if got := reality["spiderX"]; got != "/" {
		t.Errorf("spiderX = %v, want \"/\"", got)
	}
	if _, ok := reality["mldsa65Verify"]; ok {
		t.Error("mldsa65Verify present without pqv")
	}
	if got := out["streamSettings"].(map[string]any)["network"]; got != "tcp" {
		t.Errorf("network = %v, want \"tcp\" by default", got)
	}
}

// TestParseLinkErrors: every parse error has to name the field that is missing
// or wrong, because it reaches mon-server as `configError` (spec §4 step 3).
func TestParseLinkErrors(t *testing.T) {
	const base = "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@198.51.100.10:443?security=reality"
	cases := []struct {
		name string
		link string
		want string
	}{
		{"reality without fp", base + "&pbk=jNXHt1yRo0vDuchQlIP6Z0", "fp"},
		{"reality without pbk", base + "&fp=chrome", "pbk"},
		{"empty encryption", base + "&fp=chrome&pbk=k&encryption=", "encryption"},
		{"odd sid", base + "&fp=chrome&pbk=k&sid=abc", "sid"},
		{"non-hex sid", base + "&fp=chrome&pbk=k&sid=zzzz", "sid"},
		{"long sid", base + "&fp=chrome&pbk=k&sid=000102030405060708", "sid"},
		{"unknown security", "vless://id@h:443?security=vmess-aead", "security"},
		{"unknown transport", "vless://id@h:443?type=quic", "transport"},
		{"no port", "vless://id@198.51.100.10", "port"},
		{"unknown scheme", "hysteria2://id@h:443", "scheme"},
		{"empty link", "", "empty"},
		{"vmess not base64", "vmess://!!!not base64!!!", "base64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseLink(tc.link)
			if err == nil {
				t.Fatalf("ParseLink(%q) = nil error, want one", tc.link)
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
