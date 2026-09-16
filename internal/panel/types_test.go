package panel_test

import (
	"encoding/json"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
)

// The bodies below are the examples of the panel contract, copied verbatim, so
// that a drift in the wire shape shows up here first.

func TestStateDecodesTheContractExample(t *testing.T) {
	const body = `{
  "contract": 1,
  "panelVersion": "1.8.1-fork.3",
  "serverTime": 1757721600000,
  "revision": "9f2c1a7b3e5d4c60",
  "override": {"enabled": true, "host": "front.example.net"},
  "probe": {"subId": "k3j9d8s7f6g5h4j3", "lastEnsured": 1757721540000},
  "inbounds": [
    {"kind": "xray", "inboundId": 12, "tag": "inbound-443", "remark": "Reality main", "protocol": "vless", "port": 443, "enable": true},
    {"kind": "awg",  "inboundId": 0,  "tag": "awg",         "remark": "AmneziaWG",    "protocol": "awg",  "port": 51820, "enable": true}
  ],
  "stale": {"thresholdMinutes": 15}
}`
	var state panel.State
	if err := json.Unmarshal([]byte(body), &state); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if state.Contract != 1 || state.PanelVersion != "1.8.1-fork.3" || state.ServerTime != 1757721600000 {
		t.Errorf("header = %+v", state)
	}
	if state.Revision != "9f2c1a7b3e5d4c60" {
		t.Errorf("revision = %q", state.Revision)
	}
	if !state.Override.Enabled || state.Override.Host != "front.example.net" {
		t.Errorf("override = %+v", state.Override)
	}
	if !state.Probe.Ensured() || state.Probe.SubIDValue() != "k3j9d8s7f6g5h4j3" {
		t.Errorf("probe = %+v", state.Probe)
	}
	if state.Probe.LastEnsured != 1757721540000 {
		t.Errorf("lastEnsured = %d", state.Probe.LastEnsured)
	}
	want := []panel.Inbound{
		{Kind: "xray", InboundID: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
		{Kind: "awg", InboundID: 0, Tag: "awg", Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
	}
	if len(state.Inbounds) != len(want) {
		t.Fatalf("got %d inbounds, want %d", len(state.Inbounds), len(want))
	}
	for i := range want {
		if state.Inbounds[i] != want[i] {
			t.Errorf("inbounds[%d] = %+v, want %+v", i, state.Inbounds[i], want[i])
		}
	}
	if state.Stale.ThresholdMinutes != 15 {
		t.Errorf("stale = %+v", state.Stale)
	}
}

func TestProbeStateTellsNullFromEmpty(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantEnsured bool
		wantSubID   string
	}{
		{name: "never ensured", body: `{"subId": null, "lastEnsured": 0}`},
		{name: "absent", body: `{"lastEnsured": 0}`},
		{name: "ensured", body: `{"subId": "k3j9", "lastEnsured": 1}`, wantEnsured: true, wantSubID: "k3j9"},
		{name: "ensured with an empty id", body: `{"subId": "", "lastEnsured": 1}`, wantEnsured: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var probe panel.ProbeState
			if err := json.Unmarshal([]byte(tc.body), &probe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if probe.Ensured() != tc.wantEnsured {
				t.Errorf("Ensured() = %v, want %v", probe.Ensured(), tc.wantEnsured)
			}
			if probe.SubIDValue() != tc.wantSubID {
				t.Errorf("SubIDValue() = %q, want %q", probe.SubIDValue(), tc.wantSubID)
			}
		})
	}
}

func TestEventNormalizedCarriesOnlyItsKindsFields(t *testing.T) {
	// Every event starts out filled in with every field, so that a field that
	// survives Normalized is one the kind really carries.
	full := panel.Event{
		ID: "019254a0-7c3e-7d2a-9b4f-1f2e3d4c5b6a", TS: 1757721540000,
		MonClientID: "ams-1", InboundKind: panel.InboundKindXray,
		InboundID: panel.Int64Ptr(12), Path: panel.PathProxy,
		From: panel.TargetUp, To: panel.TargetDown, Reason: panel.ReasonTLSTimeout,
	}
	cases := []struct {
		name       string
		event      panel.Event
		wantFields []string
		notFields  []string
	}{
		{
			name:       "target",
			event:      func() panel.Event { e := full; e.Kind = panel.EventKindTarget; return e }(),
			wantFields: []string{"id", "ts", "kind", "monClientId", "inboundKind", "inboundId", "path", "from", "to", "reason", "notified"},
		},
		{
			name:       "mon_client",
			event:      func() panel.Event { e := full; e.Kind = panel.EventKindMonClient; return e }(),
			wantFields: []string{"id", "ts", "kind", "monClientId", "from", "to", "reason", "notified"},
			notFields:  []string{"inboundKind", "inboundId", "path"},
		},
		{
			name:       "panel",
			event:      func() panel.Event { e := full; e.Kind = panel.EventKindPanel; return e }(),
			wantFields: []string{"id", "ts", "kind", "from", "to", "reason", "notified"},
			notFields:  []string{"monClientId", "inboundKind", "inboundId", "path"},
		},
		{
			name: "awg target keeps inbound id zero",
			event: func() panel.Event {
				e := full
				e.Kind = panel.EventKindTarget
				e.InboundKind = panel.InboundKindAWG
				e.InboundID = panel.Int64Ptr(0)
				return e
			}(),
			wantFields: []string{"inboundId"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.event.Normalized())
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, name := range tc.wantFields {
				if _, ok := fields[name]; !ok {
					t.Errorf("%s is missing from %s", name, raw)
				}
			}
			for _, name := range tc.notFields {
				if _, ok := fields[name]; ok {
					t.Errorf("%s is present in %s, want it omitted", name, raw)
				}
			}
		})
	}
}

func TestEventNormalizedForcesPanelNotified(t *testing.T) {
	event := panel.Event{Kind: panel.EventKindPanel, From: panel.PanelUp, To: panel.PanelDown}
	if !event.Normalized().Notified {
		t.Error("a panel event must be notified: mon-server sends it to Telegram itself")
	}
}

func TestStatEncodesMissingLatencyAsNull(t *testing.T) {
	cases := []struct {
		name string
		stat panel.Stat
		want string
	}{
		{
			name: "no successes",
			stat: panel.Stat{
				MonClientID: "ams-1", InboundKind: panel.InboundKindXray, InboundID: 12,
				Path: panel.PathProxy, BucketStart: 1757721300000, NOk: 0, NFail: 5,
			},
			want: `{"monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy","bucketStart":1757721300000,"nOk":0,"nFail":5,"latencyMinMs":null,"latencyAvgMs":null,"latencyMaxMs":null,"handshakeMs":null}`,
		},
		{
			name: "xray with latency, no handshake",
			stat: panel.Stat{
				MonClientID: "ams-1", InboundKind: panel.InboundKindXray, InboundID: 12,
				Path: panel.PathProxy, BucketStart: 1757721300000, NOk: 5, NFail: 0,
				LatencyMinMS: panel.Int64Ptr(41), LatencyAvgMS: panel.Int64Ptr(47), LatencyMaxMS: panel.Int64Ptr(58),
			},
			want: `{"monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy","bucketStart":1757721300000,"nOk":5,"nFail":0,"latencyMinMs":41,"latencyAvgMs":47,"latencyMaxMs":58,"handshakeMs":null}`,
		},
		{
			name: "awg carries a handshake age",
			stat: panel.Stat{
				MonClientID: "ams-1", InboundKind: panel.InboundKindAWG, InboundID: 0,
				Path: panel.PathDirect, BucketStart: 1757721300000, NOk: 5,
				LatencyMinMS: panel.Int64Ptr(1), LatencyAvgMS: panel.Int64Ptr(1), LatencyMaxMS: panel.Int64Ptr(1),
				HandshakeMS: panel.Int64Ptr(31000),
			},
			want: `{"monClientId":"ams-1","inboundKind":"awg","inboundId":0,"path":"direct","bucketStart":1757721300000,"nOk":5,"nFail":0,"latencyMinMs":1,"latencyAvgMs":1,"latencyMaxMs":1,"handshakeMs":31000}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.stat)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if string(raw) != tc.want {
				t.Errorf("got  %s\nwant %s", raw, tc.want)
			}
		})
	}
}

func TestResponsesDecodeTheContractExamples(t *testing.T) {
	t.Run("probe/ensure", func(t *testing.T) {
		const body = `{"subId": "k3j9d8s7f6g5h4j3", "revision": "9f2c1a7b3e5d4c60", "lastEnsured": 1757721600000,
 "created": [{"kind":"xray","inboundId":12}], "present": 5}`
		var result panel.ProbeEnsureResult
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if result.SubID != "k3j9d8s7f6g5h4j3" || result.Present != 5 || result.LastEnsured != 1757721600000 {
			t.Errorf("result = %+v", result)
		}
		if len(result.Created) != 1 || result.Created[0] != (panel.ProbeRef{Kind: "xray", InboundID: 12}) {
			t.Errorf("created = %+v", result.Created)
		}
	})

	t.Run("probe/configs", func(t *testing.T) {
		const body = `{"revision": "9f2c1a7b3e5d4c60", "path": "direct",
 "items": [
   {"kind": "xray", "inboundId": 12, "link": "vless://uuid@203.0.113.10:443?security=reality#probe-12"},
   {"kind": "awg",  "inboundId": 0,  "filename": "probe-awg", "conf": "[Interface]\nPrivateKey = x\n"}
 ]}`
		var configs panel.ProbeConfigs
		if err := json.Unmarshal([]byte(body), &configs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if configs.Path != panel.PathDirect || len(configs.Items) != 2 {
			t.Fatalf("configs = %+v", configs)
		}
		if configs.Items[0].Link == "" || configs.Items[0].Conf != "" {
			t.Errorf("xray item = %+v, want a link and no conf", configs.Items[0])
		}
		if configs.Items[1].Filename != "probe-awg" || configs.Items[1].Conf == "" {
			t.Errorf("awg item = %+v, want a named conf", configs.Items[1])
		}
	})

	t.Run("events", func(t *testing.T) {
		const body = `{"accepted": 2, "duplicates": 0, "ignored": [{"id": "019254a0", "error": "unknown_inbound"}]}`
		var result panel.EventsResult
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if result.Accepted != 2 || result.Duplicates != 0 {
			t.Errorf("result = %+v", result)
		}
		if len(result.Ignored) != 1 || result.Ignored[0].Error != panel.CodeUnknownInbound {
			t.Errorf("ignored = %+v", result.Ignored)
		}
	})

	t.Run("stats", func(t *testing.T) {
		const body = `{"accepted": 1, "ignored": []}`
		var result panel.StatsResult
		if err := json.Unmarshal([]byte(body), &result); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if result.Accepted != 1 || len(result.Ignored) != 0 {
			t.Errorf("result = %+v", result)
		}
	})
}

func TestRequestsEncodeTheContractExamples(t *testing.T) {
	t.Run("probe/ensure", func(t *testing.T) {
		body, err := json.Marshal(panel.ProbeEnsureRequest{MonClients: []panel.MonClientSnapshot{
			{ID: "ams-1", Name: "Amsterdam #1", Region: "NL", State: panel.MonClientOnline, LastHeartbeat: 1757721590000},
		}})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		const want = `{"monClients":[{"id":"ams-1","name":"Amsterdam #1","region":"NL","state":"ONLINE","lastHeartbeat":1757721590000}]}`
		if string(body) != want {
			t.Errorf("got  %s\nwant %s", body, want)
		}
	})

	t.Run("events", func(t *testing.T) {
		body, err := json.Marshal(panel.EventsRequest{Events: []panel.Event{{
			ID: "019254a0-7c3e-7d2a-9b4f-1f2e3d4c5b6a", TS: 1757721540000, Kind: panel.EventKindTarget,
			MonClientID: "ams-1", InboundKind: panel.InboundKindXray, InboundID: panel.Int64Ptr(12),
			Path: panel.PathProxy, From: panel.TargetUp, To: panel.TargetDown,
			Reason: panel.ReasonTLSTimeout, Notified: false,
		}}})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		const want = `{"events":[{"id":"019254a0-7c3e-7d2a-9b4f-1f2e3d4c5b6a","ts":1757721540000,"kind":"target",` +
			`"monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy",` +
			`"from":"UP","to":"DOWN","reason":"tls_timeout","notified":false}]}`
		if string(body) != want {
			t.Errorf("got  %s\nwant %s", body, want)
		}
	})
}
