// Package config turns the targets of a config document (protocol §4.2) into
// the things mon-client actually runs: one xray.json for every xray-target
// (spec §4 step 2, research §2.1) and one AmneziaWG UAPI blob per AWG-target
// (spec §4 step 2, research §3.4).
//
// The package is deliberately pure: it only parses strings and produces bytes,
// so every rule below is covered by golden tests and the generated config is
// checked by the real `xray -test` (xray_integration_test.go). Nothing here
// touches the network, the filesystem or the clock.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Target is the subset of a config-document target (protocol §4.2) this package
// needs. It is a flat copy of proto.Target so that internal/client/config does
// not depend on internal/client/proto: the run loop converts field by field.
type Target struct {
	InboundKind string
	InboundID   int
	Path        string
	Protocol    string
	Link        string
	Conf        string
}

// TargetKey identifies a target inside one mon-client (protocol §4.2). It has
// the same shape as proto.TargetKey on purpose, so the app layer can convert
// between the two with a plain Go conversion.
type TargetKey struct {
	InboundKind string
	InboundID   int
	Path        string
}

// String is the key's wire form, the probe's ?target= value (protocol §5.2).
func (k TargetKey) String() string {
	return k.InboundKind + ":" + strconv.Itoa(k.InboundID) + ":" + k.Path
}

// Key is the target's identity; the rest of Target is material for the config.
func (t Target) Key() TargetKey {
	return TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundID, Path: t.Path}
}

const (
	// defaultEncryption is what a vless link without `encryption` means. The
	// core rejects an empty value with `please add/set "encryption":"none"`
	// (research §2.1), so mon-client fills it in rather than generate a
	// config that cannot start.
	defaultEncryption = "none"

	// defaultSpiderX is the Reality `spx` default (research §2.1 table).
	defaultSpiderX = "/"

	// maxShortIDLen is the Reality shortId limit: hex, at most 16 characters,
	// even length (research §2.1 table; the core validates the same).
	maxShortIDLen = 16
)

// ParseLink turns one share link (protocol §4.2 `link`) into an xray outbound
// object plus the address and port of the real server it dials. The outbound
// carries no `tag`: BuildXray adds it, because the tag is a property of the
// generated config, not of the link.
//
// Supported schemes are the four the panel generates (spec §4 step 2):
// vless, vmess (base64 JSON), trojan and shadowsocks (SIP002). Reality
// (`security=reality`) requires `fp` and `pbk` and defaults `spx` to "/";
// plain TLS and no security are accepted too. `type=tcp` and `type=raw` are
// the same transport (research §2.1); ws, grpc and xhttp are mapped as well.
//
// Errors name the missing or malformed field so that the caller can put them
// on the wire as `configError` (spec §4 step 3, first line ≤ 256 characters).
func ParseLink(link string) (map[string]any, string, int, error) {
	link = strings.TrimSpace(link)
	if link == "" {
		return nil, "", 0, errors.New("empty link")
	}
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, "", 0, errors.New("link has no scheme")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(link)
	case "vmess":
		return parseVMess(link)
	case "trojan":
		return parseTrojan(link)
	case "ss", "shadowsocks":
		return parseShadowsocks(link)
	default:
		return nil, "", 0, fmt.Errorf("unsupported link scheme %q", scheme)
	}
}

// parseVLESS maps vless://uuid@host:port?… per research §2.1.
func parseVLESS(link string) (map[string]any, string, int, error) {
	u, addr, port, err := parseURLLink(link)
	if err != nil {
		return nil, "", 0, err
	}
	id := u.User.Username()
	if id == "" {
		return nil, "", 0, errors.New("vless link has no uuid")
	}
	q := u.Query()

	// An explicitly empty `encryption` is an error rather than a silent
	// default: the core refuses such an outbound, and failing here names the
	// target instead of only showing up in `xray -test` output.
	enc := defaultEncryption
	if vals, present := q["encryption"]; present {
		if vals[0] == "" {
			return nil, "", 0, errors.New("vless link has an empty encryption (must be \"none\")")
		}
		enc = vals[0]
	}

	user := map[string]any{"id": id, "encryption": enc}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	stream, err := buildStream(q)
	if err != nil {
		return nil, "", 0, err
	}
	out := map[string]any{
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": addr,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": stream,
		"mux":            muxOff(),
	}
	return out, addr, port, nil
}

// parseVMess maps vmess://<base64 JSON> (the panel builds it in
// sub/subService.go buildVmessLink) onto a vmess outbound.
func parseVMess(link string) (map[string]any, string, int, error) {
	raw, err := decodeBase64(strings.TrimPrefix(link[len("vmess"):], "://"))
	if err != nil {
		return nil, "", 0, fmt.Errorf("vmess link is not base64: %w", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, "", 0, fmt.Errorf("vmess link is not JSON: %w", err)
	}
	addr := jsonString(obj["add"])
	if addr == "" {
		return nil, "", 0, errors.New("vmess link has no add (address)")
	}
	port, err := jsonInt(obj["port"])
	if err != nil {
		return nil, "", 0, fmt.Errorf("vmess link has a bad port: %w", err)
	}
	id := jsonString(obj["id"])
	if id == "" {
		return nil, "", 0, errors.New("vmess link has no id (uuid)")
	}
	user := map[string]any{"id": id, "security": orDefault(jsonString(obj["scy"]), "auto")}
	if aid, err := jsonInt(obj["aid"]); err == nil && aid > 0 {
		user["alterId"] = aid
	}

	// The base64 object uses the vmess field names (net/type/host/path/tls/…);
	// translate them to the same query keys buildStream understands so that
	// every protocol shares one transport/security mapping.
	q := url.Values{}
	setIf := func(key, val string) {
		if val != "" {
			q.Set(key, val)
		}
	}
	setIf("type", orDefault(jsonString(obj["net"]), "tcp"))
	setIf("headerType", jsonString(obj["type"]))
	setIf("host", jsonString(obj["host"]))
	setIf("path", jsonString(obj["path"]))
	setIf("serviceName", jsonString(obj["path"]))
	setIf("mode", jsonString(obj["mode"]))
	setIf("security", jsonString(obj["tls"]))
	setIf("sni", jsonString(obj["sni"]))
	setIf("fp", jsonString(obj["fp"]))
	setIf("alpn", jsonString(obj["alpn"]))
	if q.Get("headerType") == "none" {
		q.Del("headerType")
	}
	stream, err := buildStream(q)
	if err != nil {
		return nil, "", 0, err
	}
	out := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": addr,
				"port":    port,
				"users":   []any{user},
			}},
		},
		"streamSettings": stream,
		"mux":            muxOff(),
	}
	return out, addr, port, nil
}

// parseTrojan maps trojan://password@host:port?… (panel: genTrojanLink).
func parseTrojan(link string) (map[string]any, string, int, error) {
	u, addr, port, err := parseURLLink(link)
	if err != nil {
		return nil, "", 0, err
	}
	password := u.User.Username()
	if password == "" {
		return nil, "", 0, errors.New("trojan link has no password")
	}
	stream, err := buildStream(u.Query())
	if err != nil {
		return nil, "", 0, err
	}
	out := map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{map[string]any{
				"address":  addr,
				"port":     port,
				"password": password,
			}},
		},
		"streamSettings": stream,
		"mux":            muxOff(),
	}
	return out, addr, port, nil
}

// parseShadowsocks maps SIP002 ss://<base64(method:password)>@host:port?…
// (panel: genShadowsocksLink). A plain, non-base64 userinfo is accepted too,
// because SIP002 allows percent-encoded `method:password`.
func parseShadowsocks(link string) (map[string]any, string, int, error) {
	u, addr, port, err := parseURLLink(link)
	if err != nil {
		return nil, "", 0, err
	}
	var userinfo string
	if pw, ok := u.User.Password(); ok {
		userinfo = u.User.Username() + ":" + pw
	} else if decoded, err := decodeBase64(u.User.Username()); err == nil && strings.Contains(string(decoded), ":") {
		userinfo = string(decoded)
	} else {
		userinfo = u.User.Username()
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" {
		return nil, "", 0, errors.New("shadowsocks link has no method:password userinfo")
	}
	if password == "" {
		return nil, "", 0, errors.New("shadowsocks link has no password")
	}
	stream, err := buildStream(u.Query())
	if err != nil {
		return nil, "", 0, err
	}
	out := map[string]any{
		"protocol": "shadowsocks",
		"settings": map[string]any{
			"servers": []any{map[string]any{
				"address":  addr,
				"port":     port,
				"method":   method,
				"password": password,
			}},
		},
		"streamSettings": stream,
		"mux":            muxOff(),
	}
	return out, addr, port, nil
}

// parseURLLink is the shared `scheme://userinfo@host:port?query#remark` part.
func parseURLLink(link string) (*url.URL, string, int, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", 0, fmt.Errorf("malformed link: %w", err)
	}
	addr := u.Hostname()
	if addr == "" {
		return nil, "", 0, errors.New("link has no host")
	}
	if u.Port() == "" {
		return nil, "", 0, errors.New("link has no port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		return nil, "", 0, fmt.Errorf("link has a bad port %q", u.Port())
	}
	return u, addr, port, nil
}

// buildStream maps the transport and security query parameters of a share link
// onto `streamSettings` (research §2.1 table).
func buildStream(q url.Values) (map[string]any, error) {
	network := orDefault(q.Get("type"), "tcp")
	if network == "raw" {
		// `raw` is the new name of `tcp`; the core folds them together
		// (`case "raw", "tcp": return "tcp"`, research §2.1). Normalising
		// here keeps the goldens — and the config — in one spelling.
		network = "tcp"
	}
	stream := map[string]any{"network": network}

	switch network {
	case "tcp":
		if q.Get("headerType") == "http" {
			request := map[string]any{}
			if p := q.Get("path"); p != "" {
				request["path"] = []any{p}
			}
			if h := q.Get("host"); h != "" {
				request["headers"] = map[string]any{"Host": []any{h}}
			}
			stream["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http", "request": request},
			}
		}
	case "ws":
		ws := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			ws["host"] = h
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]any{"serviceName": q.Get("serviceName")}
		if a := q.Get("authority"); a != "" {
			grpc["authority"] = a
		}
		if q.Get("mode") == "multi" {
			grpc["multiMode"] = true
		}
		stream["grpcSettings"] = grpc
	case "xhttp":
		xh := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			xh["host"] = h
		}
		if m := q.Get("mode"); m != "" {
			xh["mode"] = m
		}
		stream["xhttpSettings"] = xh
	case "httpupgrade":
		hu := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			hu["host"] = h
		}
		stream["httpupgradeSettings"] = hu
	default:
		return nil, fmt.Errorf("unsupported transport %q", network)
	}

	security := q.Get("security")
	switch security {
	case "", "none":
		stream["security"] = "none"
	case "tls":
		stream["security"] = "tls"
		tls := map[string]any{}
		if sni := q.Get("sni"); sni != "" {
			tls["serverName"] = sni
		}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := q.Get("alpn"); alpn != "" {
			var list []any
			for _, a := range strings.Split(alpn, ",") {
				if a = strings.TrimSpace(a); a != "" {
					list = append(list, a)
				}
			}
			tls["alpn"] = list
		}
		stream["tlsSettings"] = tls
	case "reality":
		reality, err := buildReality(q)
		if err != nil {
			return nil, err
		}
		stream["security"] = "reality"
		stream["realitySettings"] = reality
	default:
		return nil, fmt.Errorf("unsupported security %q", security)
	}
	return stream, nil
}

// buildReality maps sni/pbk/sid/fp/spx/pqv onto realitySettings. `fp` and
// `pbk` are mandatory and `sid` must be even-length hex of at most 16
// characters — the core rejects anything else (research §2.1), and mon-client
// would rather report a named field than an `xray -test` failure.
func buildReality(q url.Values) (map[string]any, error) {
	fp := q.Get("fp")
	if fp == "" {
		return nil, errors.New("reality link has no fp (fingerprint)")
	}
	pbk := q.Get("pbk")
	if pbk == "" {
		return nil, errors.New("reality link has no pbk (public key)")
	}
	sid := q.Get("sid")
	if len(sid) > maxShortIDLen {
		return nil, fmt.Errorf("reality sid is longer than %d characters", maxShortIDLen)
	}
	if len(sid)%2 != 0 {
		return nil, errors.New("reality sid has an odd number of hex digits")
	}
	for _, c := range sid {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return nil, fmt.Errorf("reality sid %q is not hex", sid)
		}
	}
	reality := map[string]any{
		"fingerprint": fp,
		"publicKey":   pbk,
		"serverName":  q.Get("sni"),
		"shortId":     sid,
		"show":        false,
		"spiderX":     orDefault(q.Get("spx"), defaultSpiderX),
	}
	if pqv := q.Get("pqv"); pqv != "" {
		reality["mldsa65Verify"] = pqv
	}
	return reality, nil
}

// muxOff spells out that multiplexing is disabled, so that every probe opens a
// fresh connection and therefore a fresh Reality handshake (spec §4 step 2,
// research §2.6). It is xray's default, but the probe depends on it.
func muxOff() map[string]any { return map[string]any{"enabled": false} }

// decodeBase64 accepts every spelling the panel and SIP002 use: standard and
// URL alphabets, with or without padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var err error
	for _, enc := range encs {
		var out []byte
		if out, err = enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, err
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// jsonString reads a vmess object field that may be a string or a number.
func jsonString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// jsonInt reads a vmess object field that may be a number or a numeric string.
func jsonInt(v any) (int, error) {
	switch t := v.(type) {
	case float64:
		return int(t), nil
	case string:
		return strconv.Atoi(t)
	default:
		return 0, fmt.Errorf("not a number: %v", v)
	}
}
