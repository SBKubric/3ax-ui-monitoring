package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clientcfg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	configTestToken       = "a-client-token"
	configTestMonClientID = "ams-1"
	configTestRealHost    = "203.0.113.10"
	configTestFrontHost   = "front.example.net"
	configTestPublicIP    = "198.51.100.7"
	configTestPanelRev    = "9f2c1a7b3e5d4c60"
)

// configTestAuth is the Authenticator the config endpoint runs behind: one
// known token belonging to one mon-client.
type configTestAuth struct {
	token       string
	monClientID string
}

// AuthenticateClient implements Authenticator.
func (a configTestAuth) AuthenticateClient(_ context.Context, token string) (Identity, error) {
	if token != a.token {
		return Identity{}, ErrTokenRevoked
	}
	return Identity{MonClientID: a.monClientID}, nil
}

// configFailingService stands in for a storage failure.
type configFailingService struct{ err error }

// Document implements ConfigService.
func (s configFailingService) Document(context.Context, string) (json.RawMessage, string, error) {
	return nil, "", s.err
}

// configTestStore opens a store with a mon-client registered and returns it
// with the clock it is driven by.
func configTestStore(t *testing.T, paths []string) *store.Store {
	t.Helper()
	fake := clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), slog.New(slog.DiscardHandler), store.WithClock(fake))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	settings := store.DefaultSettings()
	settings.RealHost = configTestRealHost
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	encoded, err := store.EncodePaths(paths)
	if err != nil {
		t.Fatalf("encode paths: %v", err)
	}
	row := store.MonClient{
		ID:      configTestMonClientID,
		Name:    configTestMonClientID,
		Region:  "eu",
		Paths:   encoded,
		Enabled: true,
		State:   store.ClientStateNever,
	}
	if err := st.DB().Create(&row).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}
	return st
}

// configTestInput is one panel poll's worth of material.
func configTestInput() clientcfg.Input {
	items := func(host string) []panel.ConfigItem {
		return []panel.ConfigItem{
			{Kind: panel.InboundKindXray, InboundID: 12, Link: "vless://11111111-2222-3333-4444-555555555555@" + host + ":443?security=reality&type=tcp#probe-12"},
			{Kind: panel.InboundKindAWG, InboundID: 0, Filename: "probe-awg", Conf: "[Interface]\nPrivateKey = cHJpdmF0ZQ==\n\n[Peer]\nEndpoint = " + host + ":51820\n"},
		}
	}
	return clientcfg.Input{
		PanelRevision: configTestPanelRev,
		Proxy:         &panel.ProbeConfigs{Revision: configTestPanelRev, Path: panel.PathProxy, Items: items(configTestFrontHost)},
		Direct:        &panel.ProbeConfigs{Revision: configTestPanelRev, Path: panel.PathDirect, Items: items(configTestRealHost)},
		Inbounds: []panel.Inbound{
			{Kind: panel.InboundKindXray, InboundID: 12, Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
			{Kind: panel.InboundKindAWG, InboundID: 0, Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
		},
	}
}

// configTestServer mounts GET /v1/config over svc and returns its base URL.
func configTestServer(t *testing.T, svc ConfigService) string {
	t.Helper()
	s := New(configTestAuth{token: configTestToken, monClientID: configTestMonClientID},
		clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)),
		slog.New(slog.DiscardHandler))
	RegisterConfigRoutes(s, svc)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// configGet performs GET /v1/config and returns the response and its body.
func configGet(t *testing.T, baseURL, token string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/config", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /v1/config: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func TestGetConfigServesTheStoredDocument(t *testing.T) {
	st := configTestStore(t, store.DefaultPaths())
	builder := clientcfg.New(st, clientcfg.WithProbeEndpoint(":443", configTestPublicIP))
	built, err := builder.BuildFor(context.Background(), configTestMonClientID, configTestInput())
	if err != nil {
		t.Fatalf("BuildFor: %v", err)
	}
	baseURL := configTestServer(t, builder)

	resp, body := configGet(t, baseURL, configTestToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}

	var row store.ClientConfig
	if err := st.DB().Where("mon_client_id = ?", configTestMonClientID).Take(&row).Error; err != nil {
		t.Fatalf("read client_configs: %v", err)
	}
	if body != row.Document {
		t.Errorf("body is not the stored document byte for byte:\n%s\n%s", body, row.Document)
	}
	if body != string(built.Document) {
		t.Errorf("body is not what BuildFor reported:\n%s\n%s", body, built.Document)
	}

	var served struct {
		ConfigRevision string `json:"configRevision"`
		MonClientID    string `json:"monClientId"`
		ProbeURL       string `json:"probeUrl"`
		Targets        []struct {
			Path string `json:"path"`
			Link string `json:"link"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(body), &served); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if served.ConfigRevision != row.Revision {
		t.Errorf("configRevision in the body is %q, client_configs.revision is %q", served.ConfigRevision, row.Revision)
	}
	if served.MonClientID != configTestMonClientID {
		t.Errorf("monClientId = %q", served.MonClientID)
	}
	if want := "https://" + configTestPublicIP + ":443/v1/probe"; served.ProbeURL != want {
		t.Errorf("probeUrl = %q, want %q", served.ProbeURL, want)
	}
	if len(served.Targets) != 4 {
		t.Errorf("got %d targets, want 4", len(served.Targets))
	}
	if !strings.Contains(body, "&type=tcp") {
		t.Errorf("the link's separators were re-encoded on the way out:\n%s", body)
	}
}

func TestGetConfigForAProxyOnlyMonClientHidesTheRealServer(t *testing.T) {
	st := configTestStore(t, []string{panel.PathProxy})
	builder := clientcfg.New(st, clientcfg.WithProbeEndpoint(":443", configTestPublicIP))
	if _, err := builder.BuildFor(context.Background(), configTestMonClientID, configTestInput()); err != nil {
		t.Fatalf("BuildFor: %v", err)
	}
	baseURL := configTestServer(t, builder)

	resp, body := configGet(t, baseURL, configTestToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	if strings.Contains(body, configTestRealHost) {
		t.Errorf("the real server's address reached a proxy-only mon-client:\n%s", body)
	}
}

func TestGetConfigWithoutAToken(t *testing.T) {
	baseURL := configTestServer(t, configFailingService{err: errors.New("never called")})

	tests := []struct {
		name  string
		token string
	}{
		{name: "no Authorization header", token: ""},
		{name: "a token nobody owns", token: "not-the-token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := configGet(t, baseURL, tc.token)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", resp.StatusCode, body)
			}
			var envelope ErrorBody
			if err := json.Unmarshal([]byte(body), &envelope); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if envelope.Error != ErrCodeTokenRevoked {
				t.Errorf("error = %q, want %q", envelope.Error, ErrCodeTokenRevoked)
			}
		})
	}
}

func TestGetConfigBeforeOneHasBeenBuilt(t *testing.T) {
	st := configTestStore(t, store.DefaultPaths())
	builder := clientcfg.New(st, clientcfg.WithProbeEndpoint(":443", configTestPublicIP))
	baseURL := configTestServer(t, builder)

	resp, body := configGet(t, baseURL, configTestToken)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Retry-After"); got != configRetryAfter {
		t.Errorf("Retry-After = %q, want %q", got, configRetryAfter)
	}
	var envelope ErrorBody
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if envelope.Error != ErrCodeConfigUnavailable {
		t.Errorf("error = %q, want %q", envelope.Error, ErrCodeConfigUnavailable)
	}

	// The first panel poll builds it, and the same mon-client is served
	// normally from then on.
	if _, err := builder.BuildFor(context.Background(), configTestMonClientID, configTestInput()); err != nil {
		t.Fatalf("BuildFor: %v", err)
	}
	resp, body = configGet(t, baseURL, configTestToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status after the first build = %d, want 200: %s", resp.StatusCode, body)
	}
}

func TestGetConfigWhenTheStoreFails(t *testing.T) {
	baseURL := configTestServer(t, configFailingService{err: errors.New("database is locked")})

	resp, body := configGet(t, baseURL, configTestToken)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, body)
	}
	var envelope ErrorBody
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if envelope.Error != ErrCodeInternal {
		t.Errorf("error = %q, want %q", envelope.Error, ErrCodeInternal)
	}
	if strings.Contains(body, "database is locked") {
		t.Errorf("the storage error leaked to the mon-client: %s", body)
	}
}
