package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultMTU is the MTU of an AmneziaWG tunnel when the `.conf` does not say
// otherwise (spec §4 step 2; it is also what awg-quick uses).
const DefaultMTU = 1420

// AWGConfig is one AWG-target's `.conf` (protocol §4.2 `conf`) in the shape the
// in-process netstack device needs (spec §4 step 2, research §3.4):
// netstack.CreateNetTUN takes LocalAddresses and MTU, device.IpcSet takes UAPI
// verbatim. Endpoint is the same `endpoint=` line, surfaced separately because
// the probe reports the real server it dialled.
type AWGConfig struct {
	// LocalAddresses are the [Interface] Address entries without their
	// prefix length: netstack routes by address, not by subnet.
	LocalAddresses []netip.Addr
	// MTU is [Interface] MTU or DefaultMTU.
	MTU int
	// UAPI is ready for device.IpcSet: interface keys first (private_key
	// leading), then each peer's public_key, preshared_key, endpoint and
	// allowed_ip lines. Every line is lowercase and every key is hex.
	UAPI string
	// Endpoint is the first peer's endpoint (`host:port`).
	Endpoint string
}

// interfaceUAPIKeys maps the [Interface] keys of an AmneziaWG 3.x `.conf` to
// their UAPI spelling (research §3.4). Lookup is on the key with case,
// underscores and dashes removed, so both `Jmin` and `j_min`, both
// `HeaderProtectionKey` and `header_protection_key`, are understood.
var interfaceUAPIKeys = map[string]string{
	"privatekey": "private_key",
	"listenport": "listen_port",
	"fwmark":     "fwmark",

	// AmneziaWG obfuscation parameters: junk packets (Jc/Jmin/Jmax),
	// init/response/cookie/transport padding (S1..S4), header types
	// (H1..H4) and the 3.x packet templates (I1..I5) (research §3.7).
	"jc": "jc", "jmin": "jmin", "jmax": "jmax",
	"s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4",
	"i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",

	// The rest of the AmneziaWG 3.x interface knobs (research §3.4).
	"headerprotectionkey":    "header_protection_key",
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":         "rekey_after_time",
	"rekeytimeout":           "rekey_timeout",
	"rejectaftertime":        "reject_after_time",
	"keepalivetimeout":       "keepalive_timeout",
	"maxhandshakeattempts":   "max_handshake_attempts",
	"randomtrailers":         "random_trailers",
	"disablecookies":         "disable_cookies",
}

// interfaceIgnored are [Interface] keys that describe the *interface* rather
// than the protocol: netstack gets Address and MTU as arguments, DNS is never
// used (mon-client dials mon-server by IP, spec §4 step 2), and the awg-quick
// hooks have no meaning in-process (research §3.2).
var interfaceIgnored = map[string]bool{
	"address": true, "mtu": true, "dns": true, "table": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true,
}

// hexKeyFields are the UAPI keys whose value is a 32-byte key: the `.conf`
// spells them in base64, UAPI wants hex (research §3.4).
var hexKeyFields = map[string]bool{
	"private_key": true, "public_key": true, "preshared_key": true,
	"header_protection_key": true,
}

// ParseAWGConf turns an AmneziaWG `.conf` into netstack arguments and a UAPI
// blob (spec §4 step 2, research §3.4). PersistentKeepalive is dropped — the
// probe recreates the device every cycle and never needs a NAT mapping kept
// alive (research §3.6).
//
// Errors name the section and the field at fault so the run loop can report
// them as `configError` (spec §4 step 3).
func ParseAWGConf(conf string) (*AWGConfig, error) {
	// A peer is collected field by field so that the UAPI lines always come
	// out in the order device.IpcSet expects, whatever order the `.conf`
	// happened to use (research §3.4).
	type peer struct {
		publicKey    string
		presharedKey string
		endpoint     string
		allowedIPs   []string
	}
	var (
		cfg       = AWGConfig{MTU: DefaultMTU}
		iface     []string
		privKey   string
		peers     []peer
		section   string
		sawIface  bool
		firstEndp string
	)

	for n, raw := range strings.Split(conf, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			switch section {
			case "interface":
				sawIface = true
			case "peer":
				peers = append(peers, peer{})
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", n+1, section)
			}
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: %q is not key = value", n+1, line)
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		key := normalizeConfKey(name)

		switch section {
		case "interface":
			switch {
			case key == "address":
				addrs, err := parseAddresses(value)
				if err != nil {
					return nil, fmt.Errorf("[Interface] Address: %w", err)
				}
				cfg.LocalAddresses = append(cfg.LocalAddresses, addrs...)
			case key == "mtu":
				mtu, err := strconv.Atoi(value)
				if err != nil || mtu <= 0 {
					return nil, fmt.Errorf("[Interface] MTU %q is not a positive number", value)
				}
				cfg.MTU = mtu
			case interfaceIgnored[key]:
				// DNS and the awg-quick hooks: deliberately dropped.
			default:
				uapiKey, known := interfaceUAPIKeys[key]
				if !known {
					return nil, fmt.Errorf("[Interface] has an unknown key %q", name)
				}
				v, err := uapiValue(uapiKey, value)
				if err != nil {
					return nil, fmt.Errorf("[Interface] %s: %w", name, err)
				}
				if uapiKey == "private_key" {
					privKey = v
					continue
				}
				iface = append(iface, uapiKey+"="+v)
			}
		case "peer":
			p := &peers[len(peers)-1]
			switch key {
			case "publickey":
				v, err := uapiValue("public_key", value)
				if err != nil {
					return nil, fmt.Errorf("[Peer] PublicKey: %w", err)
				}
				p.publicKey = v
			case "presharedkey":
				v, err := uapiValue("preshared_key", value)
				if err != nil {
					return nil, fmt.Errorf("[Peer] PresharedKey: %w", err)
				}
				p.presharedKey = v
			case "endpoint":
				if err := validateEndpoint(value); err != nil {
					return nil, fmt.Errorf("[Peer] Endpoint %q: %w", value, err)
				}
				p.endpoint = value
				if firstEndp == "" {
					firstEndp = value
				}
			case "allowedips":
				for _, cidr := range splitList(value) {
					if _, err := netip.ParsePrefix(cidr); err != nil {
						return nil, fmt.Errorf("[Peer] AllowedIPs %q: not a CIDR", cidr)
					}
					p.allowedIPs = append(p.allowedIPs, cidr)
				}
			case "persistentkeepalive":
				// Dropped on purpose (spec §4 step 2, research §3.6).
			default:
				return nil, fmt.Errorf("[Peer] has an unknown key %q", name)
			}
		default:
			return nil, fmt.Errorf("line %d: %q is outside any section", n+1, line)
		}
	}

	if !sawIface {
		return nil, errors.New("conf has no [Interface] section")
	}
	if privKey == "" {
		return nil, errors.New("[Interface] has no PrivateKey")
	}
	if len(cfg.LocalAddresses) == 0 {
		return nil, errors.New("[Interface] has no Address")
	}
	if len(peers) == 0 {
		return nil, errors.New("conf has no [Peer] section")
	}

	// device.IpcSet reads the interface keys first and then assigns every
	// following key to the peer opened by the last public_key, so the order
	// below is a requirement, not a style (research §3.4).
	var b strings.Builder
	b.WriteString("private_key=" + privKey + "\n")
	for _, l := range iface {
		b.WriteString(l + "\n")
	}
	for i, p := range peers {
		if p.publicKey == "" {
			return nil, fmt.Errorf("[Peer] #%d has no PublicKey", i+1)
		}
		b.WriteString("public_key=" + p.publicKey + "\n")
		if p.presharedKey != "" {
			b.WriteString("preshared_key=" + p.presharedKey + "\n")
		}
		if p.endpoint != "" {
			b.WriteString("endpoint=" + p.endpoint + "\n")
		}
		for _, cidr := range p.allowedIPs {
			b.WriteString("allowed_ip=" + cidr + "\n")
		}
	}
	cfg.UAPI = b.String()
	cfg.Endpoint = firstEndp
	return &cfg, nil
}

// normalizeConfKey folds a `.conf` key to its lookup form: `PersistentKeepalive`,
// `persistent_keepalive` and `persistent-keepalive` are the same key.
func normalizeConfKey(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r == '_' || r == '-' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// uapiValue converts one value to its UAPI form: keys from base64 to hex,
// everything else verbatim.
func uapiValue(uapiKey, value string) (string, error) {
	if !hexKeyFields[uapiKey] {
		if value == "" {
			return "", errors.New("empty value")
		}
		return value, nil
	}
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return strings.ToLower(value), nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("not base64")
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("is %d bytes, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// parseAddresses reads the [Interface] Address list, dropping prefix lengths.
func parseAddresses(value string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, item := range splitList(value) {
		if prefix, err := netip.ParsePrefix(item); err == nil {
			out = append(out, prefix.Addr())
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address", item)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errors.New("no address")
	}
	return out, nil
}

// validateEndpoint checks `host:port` (a bracketed IPv6 host included) without
// resolving anything: the device does the resolving when it dials.
func validateEndpoint(value string) error {
	i := strings.LastIndex(value, ":")
	if i <= 0 {
		return errors.New("want host:port")
	}
	port, err := strconv.Atoi(value[i+1:])
	if err != nil || port <= 0 || port > 65535 {
		return errors.New("bad port")
	}
	return nil
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
