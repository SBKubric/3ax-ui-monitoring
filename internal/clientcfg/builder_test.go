package clientcfg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Addresses the tests tell apart: the real server the panel runs on, the proxy
// front in front of it, and mon-server's own box, which is neither.
const (
	testRealHost    = "203.0.113.10"
	testFrontHost   = "front.example.net"
	testPublicIP    = "198.51.100.7"
	testListen      = ":443"
	testPanelRev    = "9f2c1a7b3e5d4c60"
	testMonClientID = "ams-1"
)

func testStore(t *testing.T) (*store.Store, *clock.Fake) {
	t.Helper()
	fake := clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), slog.New(slog.DiscardHandler), store.WithClock(fake))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, fake
}

func addMonClient(t *testing.T, st *store.Store, id string, paths []string) {
	t.Helper()
	encoded, err := store.EncodePaths(paths)
	if err != nil {
		t.Fatalf("encode paths: %v", err)
	}
	row := store.MonClient{
		ID:      id,
		Name:    id,
		Region:  "eu",
		Paths:   encoded,
		Enabled: true,
		State:   store.ClientStateNever,
	}
	if err := st.DB().Create(&row).Error; err != nil {
		t.Fatalf("create mon-client %s: %v", id, err)
	}
}

// xrayLink is a subscription link as the panel renders it for one path: the
// address is already substituted, and it carries the separators and the
// fragment that a careless encoder would mangle.
func xrayLink(host string) string {
	return "vless://11111111-2222-3333-4444-555555555555@" + host + ":443?security=reality&type=tcp&sni=www.example.com#probe-12"
}

// awgConf is an AmneziaWG configuration: multi-line text with the endpoint
// already pointed at the path's address.
func awgConf(host string) string {
	return "[Interface]\nPrivateKey = cHJpdmF0ZQ==\nAddress = 10.8.0.2/32\n\n[Peer]\nPublicKey = cHVibGlj\nEndpoint = " + host + ":51820\nAllowedIPs = 0.0.0.0/0\n"
}

func probeConfigs(path, revision, host string) *panel.ProbeConfigs {
	return &panel.ProbeConfigs{
		Revision: revision,
		Path:     path,
		Items: []panel.ConfigItem{
			{Kind: panel.InboundKindXray, InboundID: 12, Link: xrayLink(host)},
			{Kind: panel.InboundKindAWG, InboundID: 0, Filename: "probe-awg", Conf: awgConf(host)},
		},
	}
}

func stateInbounds() []panel.Inbound {
	return []panel.Inbound{
		{Kind: panel.InboundKindXray, InboundID: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
		{Kind: panel.InboundKindAWG, InboundID: 0, Tag: "awg", Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
	}
}

// scenario is one whole world a document is built in. Every field is a thing
// the specification says may or may not move the config revision.
type scenario struct {
	paths    []string
	settings store.Settings
	listen   string
	publicIP string
	input    Input
}

// baseScenario is the default installation: both paths, default probe
// parameters, the override on. Every call returns fresh slices and pointers so
// that a subtest can mutate its own copy.
func baseScenario() scenario {
	settings := store.DefaultSettings()
	settings.RealHost = testRealHost
	return scenario{
		paths:    store.DefaultPaths(),
		settings: settings,
		listen:   testListen,
		publicIP: testPublicIP,
		input: Input{
			PanelRevision: testPanelRev,
			Proxy:         probeConfigs(panel.PathProxy, testPanelRev, testFrontHost),
			Direct:        probeConfigs(panel.PathDirect, testPanelRev, testRealHost),
			Inbounds:      stateInbounds(),
		},
	}
}

// build runs the scenario against its own database and returns the result of
// building the one mon-client it registers.
func (s scenario) build(t *testing.T) Result {
	t.Helper()
	st, _ := testStore(t)
	if err := st.SaveSettings(s.settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	addMonClient(t, st, testMonClientID, s.paths)

	b := New(st, WithProbeEndpoint(s.listen, s.publicIP))
	res, err := b.BuildFor(context.Background(), testMonClientID, s.input)
	if err != nil {
		t.Fatalf("BuildFor: %v", err)
	}
	return res
}

// decode reads a built document back.
func decode(t *testing.T, raw json.RawMessage) Document {
	t.Helper()
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode document: %v\n%s", err, raw)
	}
	return doc
}

func TestBuildForProducesTheDocumentOfProtocol42(t *testing.T) {
	res := baseScenario().build(t)
	doc := decode(t, res.Document)

	if doc.ConfigRevision != res.Revision {
		t.Errorf("document carries revision %q, result reports %q", doc.ConfigRevision, res.Revision)
	}
	if doc.MonClientID != testMonClientID {
		t.Errorf("monClientId = %q, want %q", doc.MonClientID, testMonClientID)
	}
	if want := "https://" + testPublicIP + ":443/v1/probe"; doc.ProbeURL != want {
		t.Errorf("probeUrl = %q, want %q", doc.ProbeURL, want)
	}
	if want := (Probe{IntervalMs: 60000, BudgetMs: 20000, ConnectMs: 5000, TLSMs: 10000, HeadersMs: 10000, StartJitterMs: 5000, HeartbeatTimeoutMs: 10000}); doc.Probe != want {
		t.Errorf("probe = %+v, want %+v", doc.Probe, want)
	}

	wantTargets := []Target{
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathProxy},
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathDirect},
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathProxy},
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathDirect},
	}
	var gotTargets []Target
	for _, target := range doc.Targets {
		gotTargets = append(gotTargets, target.Target)
	}
	if !reflect.DeepEqual(gotTargets, wantTargets) {
		t.Errorf("targets = %+v, want %+v", gotTargets, wantTargets)
	}
	for _, target := range doc.Targets {
		switch target.InboundKind {
		case panel.InboundKindXray:
			if target.Protocol != "vless" {
				t.Errorf("xray target protocol = %q, want vless", target.Protocol)
			}
		case panel.InboundKindAWG:
			if target.Protocol != "awg" {
				t.Errorf("awg target protocol = %q, want awg", target.Protocol)
			}
		}
	}
	if !res.Changed || res.Previous != "" {
		t.Errorf("first build reported changed=%v previous=%q, want true and empty", res.Changed, res.Previous)
	}
}

func TestBuildForKeepsLinkAndConfVerbatim(t *testing.T) {
	res := baseScenario().build(t)
	doc := decode(t, res.Document)

	wanted := map[Target]struct{ link, conf string }{
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathProxy}:  {link: xrayLink(testFrontHost)},
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathDirect}: {link: xrayLink(testRealHost)},
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathProxy}:    {conf: awgConf(testFrontHost)},
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathDirect}:   {conf: awgConf(testRealHost)},
	}
	if len(doc.Targets) != len(wanted) {
		t.Fatalf("got %d targets, want %d", len(doc.Targets), len(wanted))
	}
	for _, target := range doc.Targets {
		want, ok := wanted[target.Target]
		if !ok {
			t.Errorf("unexpected target %+v", target.Target)
			continue
		}
		if target.Link != want.link {
			t.Errorf("%+v link = %q, want %q", target.Target, target.Link, want.link)
		}
		if target.Conf != want.conf {
			t.Errorf("%+v conf = %q, want %q", target.Target, target.Conf, want.conf)
		}
	}
	// The AWG server is inbound 0, and omitempty must not drop it.
	if !strings.Contains(string(res.Document), `"inboundId":0`) {
		t.Errorf("the AWG server lost its inbound id 0:\n%s", res.Document)
	}
	// The conf is multi-line text; it survives as JSON escapes and decodes
	// back to the same newlines.
	if !strings.Contains(string(res.Document), `[Interface]\nPrivateKey`) {
		t.Errorf("the AWG conf did not survive as written:\n%s", res.Document)
	}
	// Nothing re-encodes the link's separators.
	if !strings.Contains(string(res.Document), xrayLink(testRealHost)) {
		t.Errorf("the link is not in the stored bytes as the panel wrote it:\n%s", res.Document)
	}
}

func TestBuildForWithProxyOnlyNeverNamesTheRealServer(t *testing.T) {
	s := baseScenario()
	s.paths = []string{panel.PathProxy}
	res := s.build(t)

	body := string(res.Document)
	if strings.Contains(body, testRealHost) {
		t.Errorf("a proxy-only mon-client was handed the real server's address:\n%s", body)
	}
	if strings.Contains(body, `"`+panel.PathDirect+`"`) {
		t.Errorf("a proxy-only mon-client was handed a direct target:\n%s", body)
	}
	for _, target := range decode(t, res.Document).Targets {
		if target.Path != panel.PathProxy {
			t.Errorf("target %+v is not on the proxy path", target.Target)
		}
	}
	if got := len(decode(t, res.Document).Targets); got != 2 {
		t.Errorf("got %d targets, want the two inbounds on one path", got)
	}
}

func TestBuildForWithoutTheOverrideHasNoProxyTargets(t *testing.T) {
	s := baseScenario()
	// The panel answers 409 override_disabled for the proxy path, so the poll
	// has nothing to hand over for it.
	s.input.Proxy = nil
	res := s.build(t)

	doc := decode(t, res.Document)
	if len(doc.Targets) != 2 {
		t.Fatalf("got %d targets, want the two inbounds on the direct path", len(doc.Targets))
	}
	for _, target := range doc.Targets {
		if target.Path != panel.PathDirect {
			t.Errorf("target %+v is not on the direct path", target.Target)
		}
	}
	if strings.Contains(string(res.Document), testFrontHost) {
		t.Errorf("the proxy front leaked into a document built without the override:\n%s", res.Document)
	}
}

func TestBuildForWithNoPathsAndNoItems(t *testing.T) {
	s := baseScenario()
	s.paths = []string{}
	s.input.Proxy = nil
	s.input.Direct = nil
	res := s.build(t)

	if !strings.Contains(string(res.Document), `"targets":[]`) {
		t.Errorf("an empty configuration must still be a document with an empty array:\n%s", res.Document)
	}
	if res.Revision == "" {
		t.Error("an empty configuration still has a revision")
	}
}

func TestRevisionIsDeterministic(t *testing.T) {
	first := baseScenario().build(t)
	second := baseScenario().build(t)
	if first.Revision != second.Revision {
		t.Errorf("the same input built twice gave %q and %q", first.Revision, second.Revision)
	}
	if string(first.Document) != string(second.Document) {
		t.Errorf("the same input built twice gave different documents:\n%s\n%s", first.Document, second.Document)
	}
}

func TestRevisionRespondsToWhatTheDocumentSays(t *testing.T) {
	base := baseScenario().build(t)

	tests := []struct {
		name    string
		mutate  func(*scenario)
		changed bool
	}{
		{
			name:    "paths narrowed to the proxy only",
			mutate:  func(s *scenario) { s.paths = []string{panel.PathProxy} },
			changed: true,
		},
		{
			name:    "paths narrowed to the direct route only",
			mutate:  func(s *scenario) { s.paths = []string{panel.PathDirect} },
			changed: true,
		},
		{
			name:    "the same paths written in the other order",
			mutate:  func(s *scenario) { s.paths = []string{panel.PathDirect, panel.PathProxy} },
			changed: false,
		},
		{
			name:    "intervalMs",
			mutate:  func(s *scenario) { s.settings.IntervalMs = 30000 },
			changed: true,
		},
		{
			name:    "budgetMs",
			mutate:  func(s *scenario) { s.settings.BudgetMs = 25000 },
			changed: true,
		},
		{
			name:    "connectMs",
			mutate:  func(s *scenario) { s.settings.ConnectMs = 4000 },
			changed: true,
		},
		{
			name:    "tlsMs",
			mutate:  func(s *scenario) { s.settings.TLSMs = 9000 },
			changed: true,
		},
		{
			name:    "headersMs",
			mutate:  func(s *scenario) { s.settings.HeadersMs = 8000 },
			changed: true,
		},
		{
			name:    "startJitterMs",
			mutate:  func(s *scenario) { s.settings.StartJitterMs = 2500 },
			changed: true,
		},
		{
			name:    "heartbeatTimeoutMs",
			mutate:  func(s *scenario) { s.settings.HeartbeatTimeoutMs = 7000 },
			changed: true,
		},
		{
			name: "realHost, which the panel has already substituted into the direct links",
			mutate: func(s *scenario) {
				s.settings.RealHost = "203.0.113.99"
				s.input.Direct = probeConfigs(panel.PathDirect, testPanelRev, "203.0.113.99")
			},
			changed: true,
		},
		{
			name:    "the listener's port, and with it the probe url",
			mutate:  func(s *scenario) { s.listen = ":8443" },
			changed: true,
		},
		{
			name:    "mon-server's public IP, and with it the probe url",
			mutate:  func(s *scenario) { s.publicIP = "198.51.100.9" },
			changed: true,
		},
		{
			name: "a panel revision that brings a new link",
			mutate: func(s *scenario) {
				s.input.PanelRevision = "0b1c2d3e4f506172"
				s.input.Proxy = probeConfigs(panel.PathProxy, s.input.PanelRevision, "new-front.example.net")
				s.input.Direct = probeConfigs(panel.PathDirect, s.input.PanelRevision, testRealHost)
			},
			changed: true,
		},
		{
			name: "an inbound that disappeared from the probe set",
			mutate: func(s *scenario) {
				s.input.Proxy.Items = s.input.Proxy.Items[:1]
				s.input.Direct.Items = s.input.Direct.Items[:1]
			},
			changed: true,
		},
		{
			name: "an inbound remark, which the document does not carry",
			mutate: func(s *scenario) {
				s.input.Inbounds[0].Remark = "Reality main, renamed"
				s.input.Inbounds[1].Remark = "AmneziaWG, renamed"
			},
			changed: false,
		},
		{
			name: "an inbound port, which the document does not carry either",
			mutate: func(s *scenario) {
				s.input.Inbounds[0].Port = 8443
			},
			changed: false,
		},
		{
			name: "a state machine threshold, which is not a mon-client's business",
			mutate: func(s *scenario) {
				s.settings.DownAfter = 9
				s.settings.UpAfter = 8
				s.settings.FlapN = 7
				s.settings.FlapMin = 60
				s.settings.FlapHoldMin = 30
				s.settings.ClientOfflineAfter = 6
				s.settings.PanelDownAfter = 5
			},
			changed: false,
		},
		{
			name: "the panel returning the same probe set in another order",
			mutate: func(s *scenario) {
				s.input.Proxy.Items[0], s.input.Proxy.Items[1] = s.input.Proxy.Items[1], s.input.Proxy.Items[0]
				s.input.Direct.Items[0], s.input.Direct.Items[1] = s.input.Direct.Items[1], s.input.Direct.Items[0]
			},
			changed: false,
		},
		{
			name: "a panel revision with an unchanged probe set",
			mutate: func(s *scenario) {
				s.input.PanelRevision = "0b1c2d3e4f506172"
				s.input.Proxy.Revision = s.input.PanelRevision
				s.input.Direct.Revision = s.input.PanelRevision
			},
			// The revision is a hash of the document and the panel revision is
			// not in it: a panel that bumped its revision without changing
			// anything a mon-client can see must not send every mon-client
			// back for a configuration it already runs.
			changed: false,
		},
		{
			name: "the panel's filename for the AWG conf, which the document does not carry",
			mutate: func(s *scenario) {
				s.input.Proxy.Items[1].Filename = "something-else"
				s.input.Direct.Items[1].Filename = "something-else"
			},
			changed: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := baseScenario()
			tc.mutate(&s)
			got := s.build(t)
			if changed := got.Revision != base.Revision; changed != tc.changed {
				t.Errorf("revision %q vs %q: changed = %v, want %v\n%s", got.Revision, base.Revision, changed, tc.changed, got.Document)
			}
		})
	}
}

func TestBuildForStoresExactlyWhatItReports(t *testing.T) {
	st, fake := testStore(t)
	settings := store.DefaultSettings()
	settings.RealHost = testRealHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	addMonClient(t, st, testMonClientID, store.DefaultPaths())

	b := New(st, WithProbeEndpoint(testListen, testPublicIP), WithClock(fake))
	in := baseScenario().input

	res, err := b.BuildFor(context.Background(), testMonClientID, in)
	if err != nil {
		t.Fatalf("BuildFor: %v", err)
	}

	var row store.ClientConfig
	if err := st.DB().Where("mon_client_id = ?", testMonClientID).Take(&row).Error; err != nil {
		t.Fatalf("read client_configs: %v", err)
	}
	if row.Document != string(res.Document) {
		t.Errorf("stored document differs from the reported one:\n%s\n%s", row.Document, res.Document)
	}
	if row.Revision != res.Revision {
		t.Errorf("stored revision %q, reported %q", row.Revision, res.Revision)
	}
	if want := clock.MS(fake.Now()); row.BuiltAt != want {
		t.Errorf("built_at = %d, want %d", row.BuiltAt, want)
	}
	recomputed, err := RevisionOf([]byte(row.Document))
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}
	if recomputed != row.Revision {
		t.Errorf("the stored document hashes to %q, the stored revision is %q", recomputed, row.Revision)
	}

	// Document serves the stored bytes, Targets reads the same document.
	served, revision, err := b.Document(context.Background(), testMonClientID)
	if err != nil {
		t.Fatalf("Document: %v", err)
	}
	if string(served) != row.Document || revision != row.Revision {
		t.Errorf("Document served %q/%q, stored is %q/%q", served, revision, row.Document, row.Revision)
	}
	targets, err := b.Targets(context.Background(), testMonClientID)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	want := []Target{
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathProxy},
		{InboundKind: panel.InboundKindAWG, InboundID: 0, Path: panel.PathDirect},
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathProxy},
		{InboundKind: panel.InboundKindXray, InboundID: 12, Path: panel.PathDirect},
	}
	if !reflect.DeepEqual(targets, want) {
		t.Errorf("Targets = %+v, want %+v", targets, want)
	}

	// Rebuilding the same input is a no-op the mon-client never hears about.
	fake.Advance(time.Minute)
	again, err := b.BuildFor(context.Background(), testMonClientID, in)
	if err != nil {
		t.Fatalf("BuildFor again: %v", err)
	}
	if again.Changed || again.Previous != res.Revision || again.Revision != res.Revision {
		t.Errorf("rebuilding the same input reported changed=%v previous=%q revision=%q", again.Changed, again.Previous, again.Revision)
	}
}

func TestRebuildAllTouchesEveryMonClient(t *testing.T) {
	st, _ := testStore(t)
	settings := store.DefaultSettings()
	settings.RealHost = testRealHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	addMonClient(t, st, "ams-1", store.DefaultPaths())
	addMonClient(t, st, "tehran-1", []string{panel.PathProxy})
	addMonClient(t, st, "fra-1", []string{panel.PathDirect})

	b := New(st, WithProbeEndpoint(testListen, testPublicIP))
	in := baseScenario().input
	ctx := context.Background()

	first, err := b.RebuildAll(ctx, in)
	if err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	if len(first) != 3 {
		t.Fatalf("RebuildAll reported %d mon-clients, want 3", len(first))
	}
	for id, res := range first {
		if !res.Changed || res.Previous != "" || res.Revision == "" {
			t.Errorf("%s: first build reported changed=%v previous=%q revision=%q", id, res.Changed, res.Previous, res.Revision)
		}
	}
	if first["ams-1"].Revision == first["tehran-1"].Revision {
		t.Error("mon-clients with different paths got the same revision")
	}
	if strings.Contains(string(first["tehran-1"].Document), testRealHost) {
		t.Errorf("the proxy-only mon-client was handed the real server's address:\n%s", first["tehran-1"].Document)
	}

	second, err := b.RebuildAll(ctx, in)
	if err != nil {
		t.Fatalf("RebuildAll again: %v", err)
	}
	for id, res := range second {
		if res.Changed {
			t.Errorf("%s: an unchanged rebuild reported a new revision %q (was %q)", id, res.Revision, res.Previous)
		}
	}

	settings.IntervalMs = 30000
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	third, err := b.RebuildAll(ctx, in)
	if err != nil {
		t.Fatalf("RebuildAll after a probe parameter change: %v", err)
	}
	if len(third) != 3 {
		t.Fatalf("RebuildAll reported %d mon-clients, want 3", len(third))
	}
	for id, res := range third {
		if !res.Changed {
			t.Errorf("%s: a probe parameter change left the revision at %q", id, res.Revision)
		}
		if res.Previous != first[id].Revision {
			t.Errorf("%s: previous revision %q, want %q", id, res.Previous, first[id].Revision)
		}
	}
}

func TestBuilderRefusesWhatItCannotBuild(t *testing.T) {
	ctx := context.Background()

	t.Run("an unknown mon-client", func(t *testing.T) {
		st, _ := testStore(t)
		b := New(st, WithProbeEndpoint(testListen, testPublicIP))
		if _, err := b.BuildFor(ctx, "nobody", baseScenario().input); !errors.Is(err, ErrUnknownMonClient) {
			t.Errorf("BuildFor error = %v, want ErrUnknownMonClient", err)
		}
	})

	t.Run("no public address", func(t *testing.T) {
		st, _ := testStore(t)
		addMonClient(t, st, testMonClientID, store.DefaultPaths())
		b := New(st)
		if _, err := b.BuildFor(ctx, testMonClientID, baseScenario().input); !errors.Is(err, ErrNoProbeEndpoint) {
			t.Errorf("BuildFor error = %v, want ErrNoProbeEndpoint", err)
		}
		if _, err := b.RebuildAll(ctx, baseScenario().input); !errors.Is(err, ErrNoProbeEndpoint) {
			t.Errorf("RebuildAll error = %v, want ErrNoProbeEndpoint", err)
		}
	})

	t.Run("probe configs from two panel revisions", func(t *testing.T) {
		st, _ := testStore(t)
		addMonClient(t, st, testMonClientID, store.DefaultPaths())
		b := New(st, WithProbeEndpoint(testListen, testPublicIP))
		in := baseScenario().input
		in.Direct = probeConfigs(panel.PathDirect, "0b1c2d3e4f506172", testRealHost)
		if _, err := b.BuildFor(ctx, testMonClientID, in); !errors.Is(err, ErrRevisionMismatch) {
			t.Errorf("BuildFor error = %v, want ErrRevisionMismatch", err)
		}
	})

	t.Run("no configuration built yet", func(t *testing.T) {
		st, _ := testStore(t)
		addMonClient(t, st, testMonClientID, store.DefaultPaths())
		b := New(st, WithProbeEndpoint(testListen, testPublicIP))
		if _, _, err := b.Document(ctx, testMonClientID); !errors.Is(err, ErrNoConfig) {
			t.Errorf("Document error = %v, want ErrNoConfig", err)
		}
		if _, err := b.Targets(ctx, testMonClientID); !errors.Is(err, ErrNoConfig) {
			t.Errorf("Targets error = %v, want ErrNoConfig", err)
		}
	})
}

func TestBuildForReadsProtocolsFromPanelInboundsWhenTheCallerHasNone(t *testing.T) {
	st, _ := testStore(t)
	settings := store.DefaultSettings()
	settings.RealHost = testRealHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	addMonClient(t, st, testMonClientID, store.DefaultPaths())
	// What the poll mirrored from GET /state one step earlier.
	mirrored := []map[string]any{
		{"inbound_kind": panel.InboundKindXray, "inbound_id": 12, "protocol": "vless", "port": 443, "remark": "Reality main", "enable": true, "seen_revision": testPanelRev},
		{"inbound_kind": panel.InboundKindAWG, "inbound_id": 0, "protocol": "awg", "port": 51820, "remark": "AmneziaWG", "enable": true, "seen_revision": testPanelRev},
	}
	if err := st.DB().Model(&store.PanelInbound{}).Create(mirrored).Error; err != nil {
		t.Fatalf("mirror panel inbounds: %v", err)
	}

	b := New(st, WithProbeEndpoint(testListen, testPublicIP))
	in := baseScenario().input
	in.Inbounds = nil

	res, err := b.BuildFor(context.Background(), testMonClientID, in)
	if err != nil {
		t.Fatalf("BuildFor: %v", err)
	}
	// The document must be the one the caller would have got by carrying the
	// inbound list itself.
	if want := baseScenario().build(t); res.Revision != want.Revision {
		t.Errorf("revision from the mirror is %q, from the list %q\n%s\n%s", res.Revision, want.Revision, res.Document, want.Document)
	}
}

func TestRebuildAllKeepingTargets(t *testing.T) {
	st, _ := testStore(t)
	settings := store.DefaultSettings()
	settings.RealHost = testRealHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	addMonClient(t, st, "ams-1", store.DefaultPaths())
	addMonClient(t, st, "never-built", store.DefaultPaths())

	b := New(st, WithProbeEndpoint(testListen, testPublicIP))
	ctx := context.Background()
	built, err := b.BuildFor(ctx, "ams-1", baseScenario().input)
	if err != nil {
		t.Fatalf("BuildFor: %v", err)
	}

	// Saving a probe parameter changes mon-server's half of the document and
	// nothing the panel owns.
	settings.IntervalMs = 30000
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	results, err := b.RebuildAll(ctx, Input{KeepTargets: true})
	if err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	if _, ok := results["never-built"]; ok {
		t.Error("a mon-client with no document was given one out of nothing")
	}
	res, ok := results["ams-1"]
	if !ok {
		t.Fatal("ams-1 was not rebuilt")
	}
	if !res.Changed || res.Previous != built.Revision {
		t.Errorf("changed=%v previous=%q, want true and %q", res.Changed, res.Previous, built.Revision)
	}
	before, after := decode(t, built.Document), decode(t, res.Document)
	if !reflect.DeepEqual(before.Targets, after.Targets) {
		t.Errorf("the targets changed:\n%+v\n%+v", before.Targets, after.Targets)
	}
	if after.Probe.IntervalMs != 30000 {
		t.Errorf("intervalMs = %d, want the saved 30000", after.Probe.IntervalMs)
	}

	// Narrowing a mon-client's paths still applies without panel material.
	encoded, err := store.EncodePaths([]string{panel.PathProxy})
	if err != nil {
		t.Fatalf("encode paths: %v", err)
	}
	if err := st.DB().Model(&store.MonClient{}).Where("id = ?", "ams-1").Update("paths", encoded).Error; err != nil {
		t.Fatalf("narrow paths: %v", err)
	}
	narrowed, err := b.RebuildAll(ctx, Input{KeepTargets: true})
	if err != nil {
		t.Fatalf("RebuildAll after narrowing: %v", err)
	}
	if strings.Contains(string(narrowed["ams-1"].Document), testRealHost) {
		t.Errorf("a narrowed mon-client kept its direct targets:\n%s", narrowed["ams-1"].Document)
	}
	for _, target := range decode(t, narrowed["ams-1"].Document).Targets {
		if target.Path != panel.PathProxy {
			t.Errorf("target %+v is not on the proxy path", target.Target)
		}
	}
}

func TestBuildForKeepingTargetsWithoutADocument(t *testing.T) {
	st, _ := testStore(t)
	addMonClient(t, st, testMonClientID, store.DefaultPaths())
	b := New(st, WithProbeEndpoint(testListen, testPublicIP))
	if _, err := b.BuildFor(context.Background(), testMonClientID, Input{KeepTargets: true}); !errors.Is(err, ErrNoConfig) {
		t.Errorf("BuildFor error = %v, want ErrNoConfig", err)
	}
}
