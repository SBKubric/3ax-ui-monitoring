package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	// FirstSocksPort is the first loopback socks port mon-client hands to a
	// target; the next targets get the next ports (spec §4 step 2: "порты с
	// 10801 по порядку").
	FirstSocksPort = 10801

	// blackholeTag is the tag of the final outbound. Without a routing rule
	// xray sends traffic to the *first* outbound, so the list ends with a
	// blackhole and every inbound gets its own rule — a misrouted probe would
	// otherwise report a foreign tunnel as UP (research §2.1).
	blackholeTag = "block"
)

// XrayPlan is what the probe needs to reach one target through the generated
// config (spec §5): which loopback socks port belongs to it, and which real
// server address the xray stderr reader has to match `dialing TCP to
// tcp:<addr>:<port>` against (research §2.4).
type XrayPlan struct {
	Key        TargetKey
	SocksPort  int
	InboundTag string
	ServerAddr string
	ServerPort int
}

// BuildXray generates the single xray.json that serves every xray-target
// (spec §4 step 2, research §2.1): one socks inbound on 127.0.0.1 per target
// starting at firstPort, one outbound parsed from the target's link, one
// routing rule per inbound tag, and a blackhole as the last outbound.
//
// Targets without a `link` (AWG-targets) are skipped: they never reach xray.
// The order of the returned plan follows the order of targets, and the JSON is
// produced from maps, which encoding/json sorts by key — so the same document
// always yields byte-identical output and `appliedRevision` comparisons and
// goldens stay stable.
//
// An error names the offending target key and the field at fault so that the
// run loop can send it as `configError` (spec §4 step 3).
func BuildXray(targets []Target, firstPort int) ([]byte, []XrayPlan, error) {
	if firstPort <= 0 {
		firstPort = FirstSocksPort
	}
	var (
		inbounds  []any
		outbounds []any
		rules     []any
		plans     []XrayPlan
	)
	port := firstPort
	for _, t := range targets {
		if t.Link == "" {
			continue
		}
		key := t.Key()
		outbound, addr, serverPort, err := ParseLink(t.Link)
		if err != nil {
			return nil, nil, fmt.Errorf("target %s: %w", key, err)
		}
		inTag, outTag := InboundTag(key), outboundTag(key)
		outbound["tag"] = outTag

		inbounds = append(inbounds, map[string]any{
			"tag":      inTag,
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		})
		outbounds = append(outbounds, outbound)
		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []any{inTag},
			"outboundTag": outTag,
		})
		plans = append(plans, XrayPlan{
			Key:        key,
			SocksPort:  port,
			InboundTag: inTag,
			ServerAddr: addr,
			ServerPort: serverPort,
		})
		port++
	}

	outbounds = append(outbounds, map[string]any{"tag": blackholeTag, "protocol": "blackhole"})
	cfg := map[string]any{
		// loglevel info is what makes `dialing TCP to …` and the final
		// `failed to process outbound traffic` lines appear, which is how a
		// probe failure is attributed to a target (spec §5, research §2.4).
		"log":       map[string]any{"loglevel": "info", "access": "none"},
		"inbounds":  orEmpty(inbounds),
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": orEmpty(rules)},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal xray config: %w", err)
	}
	return append(raw, '\n'), plans, nil
}

// InboundTag is the socks inbound's tag, "in-<kind>-<inboundId>-<path>"
// (spec §4 step 2). The xray log reader and the routing rules both use it.
func InboundTag(k TargetKey) string { return tag("in", k) }

// outboundTag mirrors InboundTag for the outbound side.
func outboundTag(k TargetKey) string { return tag("out", k) }

func tag(prefix string, k TargetKey) string {
	return strings.Join([]string{prefix, k.InboundKind, strconv.Itoa(k.InboundID), k.Path}, "-")
}

// orEmpty keeps an empty list an empty JSON array instead of null: a config
// with no targets still has to be a valid document (spec §4 step 4).
func orEmpty(v []any) []any {
	if v == nil {
		return []any{}
	}
	return v
}
