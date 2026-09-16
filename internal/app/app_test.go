package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlstest"
)

// newApp builds an App the way a box would, but on a loopback port with a
// self-signed certificate, so no test can reach a certificate authority.
func newApp(t *testing.T) (*App, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := tlstest.WritePair(dir, "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the generated certificate is not a usable PEM")
	}

	a, err := New(Options{
		Config: config.Config{
			Listen:   "127.0.0.1:0",
			PublicIP: "203.0.113.10",
			DataDir:  filepath.Join(dir, "data"),
			TLS:      config.TLS{Mode: config.TLSModeFiles, Cert: certFile, Key: keyFile},
		},
		Version: "test",
		Log:     slog.New(slog.DiscardHandler),
		Clock:   clock.System{},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a, pool
}

// TestAppServesEverySurface is the wiring test: one listener answering the
// health check, the mon-client protocol and the admin UI, each with the
// behaviour its own package promises.
func TestAppServesEverySurface(t *testing.T) {
	a, pool := newApp(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	base := "https://" + a.Addr()

	tests := []struct {
		name string
		path string
		want int
	}{
		// No authentication, no database, so a health check keeps working
		// even when the panel and the certificate are unhappy.
		{name: "health check", path: "/healthz", want: http.StatusOK},
		// The protocol answers, and answers that the caller is unknown.
		{name: "config without a token", path: "/v1/config", want: http.StatusUnauthorized},
		{name: "probe without a token", path: "/v1/probe?target=xray:1:proxy&n=abc", want: http.StatusUnauthorized},
		// A page asks for a login, the JSON API refuses outright, so the UI
		// can tell the difference.
		{name: "admin page without a session", path: "/admin/requests", want: http.StatusSeeOther},
		{name: "admin api without a session", path: "/admin/api/clients", want: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Get(base + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("GET %s = %d, want %d", tc.path, resp.StatusCode, tc.want)
			}
		})
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestPollIsSkippedUntilThePanelIsConfigured: a freshly installed box has no
// panel address yet. That is a normal state, not a panel failure, and it must
// never count towards declaring the panel down.
func TestPollIsSkippedUntilThePanelIsConfigured(t *testing.T) {
	a, _ := newApp(t)

	if _, err := a.currentPoller(); !errors.Is(err, errNoPanelSettings) {
		t.Fatalf("currentPoller with no settings = %v, want errNoPanelSettings", err)
	}

	// A url without a token, and a token without a url, are both incomplete.
	for _, tc := range []struct{ url, token string }{
		{url: "https://panel.example.net/", token: ""},
		{url: "", token: "secret"},
	} {
		saveSettings(t, a.store, tc.url, tc.token)
		if _, err := a.currentPoller(); !errors.Is(err, errNoPanelSettings) {
			t.Errorf("currentPoller with url %q token %q = %v, want errNoPanelSettings", tc.url, tc.token, err)
		}
	}

	// pollOnce must swallow it rather than propagate: the loop keeps ticking.
	a.pollOnce(context.Background())
}

// TestPollerIsRebuiltWhenThePanelSettingsChange: correcting the panel address
// in the admin UI has to take effect without a restart, while an unchanged
// setting must keep the same poller, because its three-strike counter and its
// alert suppression live in memory.
func TestPollerIsRebuiltWhenThePanelSettingsChange(t *testing.T) {
	a, _ := newApp(t)
	saveSettings(t, a.store, "https://panel.example.net/", "first-token")

	first, err := a.currentPoller()
	if err != nil {
		t.Fatalf("currentPoller: %v", err)
	}
	again, err := a.currentPoller()
	if err != nil {
		t.Fatalf("currentPoller: %v", err)
	}
	if first != again {
		t.Error("the poller was rebuilt although nothing changed, which resets the PANEL_DOWN counter every cycle")
	}

	saveSettings(t, a.store, "https://panel.example.net/", "second-token")
	afterToken, err := a.currentPoller()
	if err != nil {
		t.Fatalf("currentPoller: %v", err)
	}
	if afterToken == first {
		t.Error("a new monitoring token did not rebuild the poller")
	}

	saveSettings(t, a.store, "https://other.example.net/", "second-token")
	afterURL, err := a.currentPoller()
	if err != nil {
		t.Fatalf("currentPoller: %v", err)
	}
	if afterURL == afterToken {
		t.Error("a new panel address did not rebuild the poller")
	}
}

// TestPollCycleAgainstAPanel walks the wiring end to end against a stub panel:
// one cycle must mirror the panel's inbounds, hand over the registry snapshot
// and record what it saw, without any package having been told about another.
func TestPollCycleAgainstAPanel(t *testing.T) {
	a, _ := newApp(t)

	stub := paneltest.NewStub(t)
	stub.SetToken("monitoring-token")
	stub.SetOverride(true, "front.example.net")
	stub.SetInbounds(
		panel.Inbound{Kind: panel.InboundKindXray, InboundID: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
		panel.Inbound{Kind: panel.InboundKindAWG, InboundID: 0, Tag: "awg", Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
	)
	saveSettingsFull(t, a.store, stub.URL(), "monitoring-token", "203.0.113.10")

	if err := a.pollOnceErr(context.Background()); err != nil {
		t.Fatalf("poll cycle: %v", err)
	}

	panelState, err := a.store.PanelState()
	if err != nil {
		t.Fatalf("panel state: %v", err)
	}
	if panelState.LastRevision == "" {
		t.Error("the cycle did not record the panel revision")
	}
	if panelState.Status != store.PanelStatusUp {
		t.Errorf("panel status = %q, want %q", panelState.Status, store.PanelStatusUp)
	}
	if !panelState.OverrideEnabled || panelState.OverrideHost != "front.example.net" {
		t.Errorf("the host override was not recorded: %+v", panelState)
	}

	var mirrored int64
	if err := a.store.DB().Model(&store.PanelInbound{}).Count(&mirrored).Error; err != nil {
		t.Fatalf("count inbounds: %v", err)
	}
	if mirrored != 2 {
		t.Errorf("mirrored inbounds = %d, want 2", mirrored)
	}

	if len(stub.EnsureSnapshots()) == 0 {
		t.Error("the panel was never handed a registry snapshot")
	}
}

// pollOnceErr is pollOnce without swallowing, for tests that want the failure.
func (a *App) pollOnceErr(ctx context.Context) error {
	poller, err := a.currentPoller()
	if err != nil {
		return err
	}
	return poller.PollOnce(ctx)
}

func saveSettings(t *testing.T, st *store.Store, panelURL, monToken string) {
	t.Helper()
	saveSettingsFull(t, st, panelURL, monToken, "")
}

func saveSettingsFull(t *testing.T, st *store.Store, panelURL, monToken, realHost string) {
	t.Helper()
	settings, err := st.Settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	settings.PanelURL = panelURL
	settings.MonToken = monToken
	settings.RealHost = realHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
}

// TestAMonClientApprovedBetweenRevisionsGetsAConfig is the regression test for
// the worst bug the review found: probe material was refetched only when the
// panel's revision changed, so a mon-client approved at any other moment had
// no configuration document, no target rows, and every heartbeat result it
// sent was silently discarded — indefinitely, since the panel had no reason to
// change anything.
func TestAMonClientApprovedBetweenRevisionsGetsAConfig(t *testing.T) {
	a, _ := newApp(t)

	stub := paneltest.NewStub(t)
	stub.SetToken("monitoring-token")
	stub.SetInbounds(
		panel.Inbound{Kind: panel.InboundKindXray, InboundID: 12, Protocol: "vless", Port: 443, Enable: true},
	)
	saveSettingsFull(t, a.store, stub.URL(), "monitoring-token", "203.0.113.10")

	ctx := context.Background()

	// A first cycle, with an empty registry: the revision is recorded.
	if err := a.pollOnceErr(ctx); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	before, err := a.store.PanelState()
	if err != nil {
		t.Fatalf("panel state: %v", err)
	}
	if before.LastRevision == "" {
		t.Fatal("the first cycle recorded no revision")
	}

	// Now a mon-client is approved. The panel has changed nothing.
	mc := store.MonClient{ID: "ams-1", Name: "Amsterdam #1", Region: "NL", Enabled: true, State: store.ClientStateNever}
	if err := a.store.DB().Create(&mc).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}

	wanted, err := a.needsRebuild(ctx)
	if err != nil {
		t.Fatalf("needsRebuild: %v", err)
	}
	if !wanted {
		t.Fatal("a mon-client with no configuration did not ask for a rebuild")
	}

	if err := a.pollOnceErr(ctx); err != nil {
		t.Fatalf("second cycle: %v", err)
	}

	document, revision, err := a.configs.Document(ctx, "ams-1")
	if err != nil {
		t.Fatalf("the mon-client still has no configuration: %v", err)
	}
	if revision == "" || len(document) == 0 {
		t.Fatalf("empty configuration: revision %q, %d bytes", revision, len(document))
	}

	// And its targets exist, or every result it reports would be discarded.
	var targets int64
	if err := a.store.DB().Model(&store.Target{}).Where("mon_client_id = ?", "ams-1").Count(&targets).Error; err != nil {
		t.Fatalf("count targets: %v", err)
	}
	if targets == 0 {
		t.Error("the mon-client has no target rows, so its heartbeats would be discarded")
	}

	// The panel's revision never moved; this was mon-server's own doing.
	after, err := a.store.PanelState()
	if err != nil {
		t.Fatalf("panel state: %v", err)
	}
	if after.LastRevision != before.LastRevision {
		t.Errorf("the panel revision changed (%q → %q); the test no longer proves what it claims",
			before.LastRevision, after.LastRevision)
	}

	// With everything built, nothing asks for another rebuild.
	wanted, err = a.needsRebuild(ctx)
	if err != nil {
		t.Fatalf("needsRebuild: %v", err)
	}
	if wanted {
		t.Error("a rebuild is still wanted after every mon-client has a configuration, so every cycle would refetch")
	}
}

// TestRequestRebuildIsHonouredAndCleared: an explicit request survives until a
// rebuild actually runs, so a cycle that fails first does not swallow it.
func TestRequestRebuildIsHonouredAndCleared(t *testing.T) {
	a, _ := newApp(t)
	ctx := context.Background()

	if wanted, err := a.needsRebuild(ctx); err != nil || wanted {
		t.Fatalf("a fresh app wants a rebuild: %v, %v", wanted, err)
	}

	a.requestRebuild()
	if wanted, err := a.needsRebuild(ctx); err != nil || !wanted {
		t.Fatalf("an explicit request was not honoured: %v, %v", wanted, err)
	}
	// Still wanted: nothing has rebuilt anything yet.
	if wanted, _ := a.needsRebuild(ctx); !wanted {
		t.Error("the request was consumed by merely being read, so a failed cycle would lose it")
	}

	// The loop is woken, and a second request does not block on the full channel.
	select {
	case <-a.pollNow:
	default:
		t.Error("the poll loop was not woken")
	}
	a.requestRebuild()
	a.requestRebuild()

	if err := a.rebuildConfigs(ctx, nil); err != nil {
		t.Fatalf("rebuildConfigs: %v", err)
	}
	if wanted, err := a.needsRebuild(ctx); err != nil || wanted {
		t.Errorf("the request survived a completed rebuild: %v, %v", wanted, err)
	}
}

// TestSnapshotIsCappedAtTheContractLimit: over the limit the panel refuses the
// whole request, which would stop the probe accounts being maintained at all.
// Losing the tail of a very large registry is the lesser harm.
func TestSnapshotIsCappedAtTheContractLimit(t *testing.T) {
	a, _ := newApp(t)

	for i := range panel.MaxMonClients + 5 {
		mc := store.MonClient{
			ID:      fmt.Sprintf("box-%03d", i),
			Name:    fmt.Sprintf("Box %d", i),
			Region:  "NL",
			Enabled: true,
			State:   store.ClientStateNever,
		}
		if err := a.store.DB().Create(&mc).Error; err != nil {
			t.Fatalf("create mon-client %d: %v", i, err)
		}
	}

	snapshot, err := a.snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot) != panel.MaxMonClients {
		t.Errorf("snapshot carries %d mon-clients, want the contract limit of %d", len(snapshot), panel.MaxMonClients)
	}
}
