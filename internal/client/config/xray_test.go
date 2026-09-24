package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// twoTargets is the fixture every xray.json test uses: two xray-targets of one
// inbound (the two paths of spec §4) plus an AWG-target, which must not reach
// the xray config at all.
func twoTargets(t *testing.T) []proto.Target {
	t.Helper()
	return []proto.Target{
		{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"}, Protocol: "vless", Link: vlessRealityLink},
		{TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "direct"}, Protocol: "trojan", Link: trojanGRPCLink},
		{TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}, Protocol: "awg", Conf: readConf(t)},
	}
}

// TestBuildXrayGolden pins the whole generated xray.json for two targets
// (spec §4 step 2, research §2.1): socks inbounds from 10801, one rule per
// inbound tag, blackhole last, log info/none, mux off.
func TestBuildXrayGolden(t *testing.T) {
	cfg, plans, err := BuildXray(twoTargets(t), FirstSocksPort)
	if err != nil {
		t.Fatalf("BuildXray: %v", err)
	}
	golden(t, "xray-two-targets.json", cfg)

	want := []XrayPlan{
		{
			Key:         proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"},
			SocksPort:   10801,
			InboundTag:  "in-xray-12-proxy",
			OutboundTag: "out-xray-12-proxy",
			ServerAddr:  "198.51.100.10",
			ServerPort:  443,
		},
		{
			Key:         proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "direct"},
			SocksPort:   10802,
			InboundTag:  "in-xray-12-direct",
			OutboundTag: "out-xray-12-direct",
			ServerAddr:  "198.51.100.20",
			ServerPort:  443,
		},
	}
	if len(plans) != len(want) {
		t.Fatalf("plan has %d entries, want %d (the AWG-target must be skipped)", len(plans), len(want))
	}
	for i := range want {
		if plans[i] != want[i] {
			t.Errorf("plan[%d] = %+v, want %+v", i, plans[i], want[i])
		}
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatalf("generated config is not JSON: %v", err)
	}
	last := doc.Outbounds[len(doc.Outbounds)-1]
	if last["protocol"] != "blackhole" {
		t.Errorf("last outbound is %v, want blackhole (traffic without a rule takes the first outbound, "+
			"so the list must end with one)", last["protocol"])
	}
}

// TestBuildXrayDeterministic: the same targets must produce byte-identical
// JSON, because the file is written on every config apply and compared by the
// goldens (BuildXray's doc comment).
func TestBuildXrayDeterministic(t *testing.T) {
	first, _, err := BuildXray(twoTargets(t), FirstSocksPort)
	if err != nil {
		t.Fatalf("BuildXray: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, _, err := BuildXray(twoTargets(t), FirstSocksPort)
		if err != nil {
			t.Fatalf("BuildXray: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("BuildXray is not deterministic")
		}
	}
}

// TestBuildXrayEmpty: a mon-client whose config has no xray-targets still gets
// a valid document — the cycle simply runs empty (spec §4 step 4).
func TestBuildXrayEmpty(t *testing.T) {
	cfg, plans, err := BuildXray(nil, FirstSocksPort)
	if err != nil {
		t.Fatalf("BuildXray: %v", err)
	}
	if len(plans) != 0 {
		t.Errorf("plan = %v, want empty", plans)
	}
	if !strings.Contains(string(cfg), `"inbounds": []`) {
		t.Errorf("inbounds is not an empty array:\n%s", cfg)
	}
}

// TestBuildXrayErrorNamesTarget: a link that does not parse must fail with the
// target key in the message, because that text becomes `configError` and the
// operator has to know which target is broken (spec §4 step 3).
func TestBuildXrayErrorNamesTarget(t *testing.T) {
	targets := []proto.Target{{
		TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 7, Path: "proxy"},
		Protocol:  "vless",
		Link:      "vless://id@198.51.100.10:443?security=reality&pbk=k", // no fp
	}}
	_, _, err := BuildXray(targets, FirstSocksPort)
	if err == nil {
		t.Fatal("BuildXray = nil error, want one")
	}
	if !strings.Contains(err.Error(), "xray:7:proxy") || !strings.Contains(err.Error(), "fp") {
		t.Errorf("error %q names neither the target key nor the missing field", err)
	}
	if len(err.Error()) > 256 {
		t.Errorf("error is %d characters, longer than the configError limit of 256", len(err.Error()))
	}
}
