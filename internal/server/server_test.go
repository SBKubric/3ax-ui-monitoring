package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/server"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlstest"
)

// acmeTLS1Protocol is the ALPN protocol of the tls-alpn-01 challenge.
const acmeTLS1Protocol = "acme-tls/1"

func testClock() clock.Clock {
	return clock.NewFake(time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC))
}

// echoHandler records the path it was reached at, so a test can prove the mux
// mounts a group without stripping its prefix.
func echoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, name+" "+r.URL.Path)
	})
}

// start builds a server on a free loopback port and serves it until the test
// ends.
func start(t *testing.T, o server.Options) (*server.Server, <-chan error) {
	t.Helper()

	if o.Addr == "" {
		o.Addr = "127.0.0.1:0"
	}
	if o.Clock == nil {
		o.Clock = testClock()
	}
	srv, err := server.New(o)
	if err != nil {
		t.Fatalf("server.New() = %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(t.Context()) }()
	t.Cleanup(func() { shutdown(t, srv) })
	return srv, served
}

// TestHealthzOverTLS runs the listener the way production does, with a
// certificate from tls.mode=files, and fetches /healthz over HTTPS.
func TestHealthzOverTLS(t *testing.T) {
	t.Parallel()

	certFile, keyFile, err := tlstest.WritePair(t.TempDir(), "127.0.0.1")
	if err != nil {
		t.Fatalf("WritePair() = %v", err)
	}
	tlsConfig, err := tlsx.TLSConfig(t.Context(), tlsx.Options{
		Mode:     tlsx.ModeFiles,
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("tlsx.TLSConfig() = %v", err)
	}

	srv, _ := start(t, server.Options{TLSConfig: tlsConfig})
	client := httpsClient(t, certFile)

	resp, err := client.Get("https://" + srv.Addr() + server.HealthPath)
	if err != nil {
		t.Fatalf("GET /healthz = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body = %v", err)
	}
	if strings.TrimSpace(string(body)) == "" {
		t.Error("body is empty, want a tiny plain body")
	}
	// HTTP/2 must survive next to the ACME protocol in NextProtos.
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("proto = %q, want HTTP/2.0 to be negotiated over ALPN", resp.Proto)
	}
}

// TestTLSALPNChallengeShares443 proves the claim of mon-server.md §2.1: the
// same listener that serves traffic also answers the acme-tls/1 handshake a
// Let's Encrypt validator makes, so no second port is needed.
func TestTLSALPNChallengeShares443(t *testing.T) {
	t.Parallel()

	certFile, keyFile, err := tlstest.WritePair(t.TempDir(), "127.0.0.1")
	if err != nil {
		t.Fatalf("WritePair() = %v", err)
	}
	tlsConfig, err := tlsx.TLSConfig(t.Context(), tlsx.Options{
		Mode:     tlsx.ModeFiles,
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatalf("tlsx.TLSConfig() = %v", err)
	}
	// What tlsx returns in acme-ip mode: the challenge protocol in front.
	tlsConfig.NextProtos = []string{acmeTLS1Protocol}

	srv, _ := start(t, server.Options{TLSConfig: tlsConfig})

	tests := map[string]struct {
		offered []string
		want    string
	}{
		"acme validator": {offered: []string{acmeTLS1Protocol}, want: acmeTLS1Protocol},
		"mon-client":     {offered: []string{"h2", "http/1.1"}, want: "h2"},
		"no alpn":        {offered: nil, want: ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			conn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{
				RootCAs:    certPool(t, certFile),
				ServerName: "127.0.0.1",
				NextProtos: tt.offered,
			})
			if err != nil {
				t.Fatalf("tls.Dial() = %v", err)
			}
			defer conn.Close()

			if got := conn.ConnectionState().NegotiatedProtocol; got != tt.want {
				t.Errorf("negotiated protocol = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRouting(t *testing.T) {
	t.Parallel()

	srv, err := server.New(server.Options{
		Addr:  "127.0.0.1:0",
		V1:    echoHandler("v1"),
		Admin: echoHandler("admin"),
		Clock: testClock(),
	})
	if err != nil {
		t.Fatalf("server.New() = %v", err)
	}
	t.Cleanup(func() { shutdown(t, srv) })

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		// The groups keep their prefix: they register full patterns.
		{name: "v1 config", method: http.MethodGet, path: "/v1/config", wantStatus: http.StatusOK, wantBody: "v1 /v1/config"},
		{name: "v1 heartbeat", method: http.MethodPost, path: "/v1/heartbeat", wantStatus: http.StatusOK, wantBody: "v1 /v1/heartbeat"},
		{name: "v1 register poll", method: http.MethodGet, path: "/v1/register/abc", wantStatus: http.StatusOK, wantBody: "v1 /v1/register/abc"},
		{name: "admin page", method: http.MethodGet, path: "/admin/requests", wantStatus: http.StatusOK, wantBody: "admin /admin/requests"},
		{name: "admin api", method: http.MethodPost, path: "/admin/api/settings", wantStatus: http.StatusOK, wantBody: "admin /admin/api/settings"},
		{name: "healthz", method: http.MethodGet, path: server.HealthPath, wantStatus: http.StatusOK, wantBody: "ok"},
		{name: "healthz accepts any method", method: http.MethodPost, path: server.HealthPath, wantStatus: http.StatusOK, wantBody: "ok"},
		{name: "unknown path", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound},
		{name: "healthz is exact", method: http.MethodGet, path: "/healthz/extra", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			// No credentials of any kind on the request.
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && strings.TrimSpace(rec.Body.String()) != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

// TestNilGroups covers the bootstrap state where a group does not exist yet.
func TestNilGroups(t *testing.T) {
	t.Parallel()

	srv, _ := start(t, server.Options{})
	base := "http://" + srv.Addr()

	for _, path := range []string{"/v1/config", "/admin/requests"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s = %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
		}
	}

	resp, err := http.Get(base + server.HealthPath)
	if err != nil {
		t.Fatalf("GET /healthz = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want %d without any group mounted", resp.StatusCode, http.StatusOK)
	}
}

// TestGracefulShutdown drives the §2 requirement that a shutdown waits for the
// handlers that are already running.
func TestGracefulShutdown(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "finished")
	})

	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", V1: handler, Clock: testClock()})
	if err != nil {
		t.Fatalf("server.New() = %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(t.Context()) }()

	type result struct {
		body string
		code int
		err  error
	}
	responded := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + srv.Addr() + "/v1/slow")
		if err != nil {
			responded <- result{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		responded <- result{body: string(body), code: resp.StatusCode, err: err}
	}()

	<-entered // the handler is running

	shutdown := make(chan error, 1)
	go func() { shutdown <- srv.Shutdown(t.Context()) }()

	// Serve returns as soon as Shutdown closes the listener, which is the
	// deterministic signal that the shutdown is under way.
	if err := <-served; err != nil {
		t.Fatalf("Serve() = %v, want nil after Shutdown", err)
	}
	select {
	case err := <-shutdown:
		t.Fatalf("Shutdown() returned %v while a handler was still running", err)
	default:
	}

	close(release)

	got := <-responded
	if got.err != nil {
		t.Fatalf("in-flight request failed: %v", got.err)
	}
	if got.code != http.StatusOK || got.body != "finished" {
		t.Errorf("in-flight response = %d %q, want 200 %q", got.code, got.body, "finished")
	}
	if err := <-shutdown; err != nil {
		t.Errorf("Shutdown() = %v, want nil", err)
	}
}

// TestServeStopsOnContextCancel covers the other half of the shutdown
// contract: cancelling the context Serve was given drains the handlers too,
// and Serve only returns once they are done.
func TestServeStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})

	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", V1: handler, Clock: testClock()})
	if err != nil {
		t.Fatalf("server.New() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	status := make(chan int, 1)
	failed := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + srv.Addr() + "/v1/slow")
		if err != nil {
			failed <- err
			return
		}
		defer resp.Body.Close()
		status <- resp.StatusCode
	}()

	<-entered
	cancel()
	close(release)

	select {
	case err := <-failed:
		t.Fatalf("in-flight request failed: %v", err)
	case code := <-status:
		if code != http.StatusNoContent {
			t.Errorf("in-flight status = %d, want %d", code, http.StatusNoContent)
		}
	}
	if err := <-served; err != nil {
		t.Errorf("Serve() = %v, want nil after the context was cancelled", err)
	}
}

// TestShutdownBeforeServe releases the bound port even if Serve never ran.
func TestShutdownBeforeServe(t *testing.T) {
	t.Parallel()

	srv, err := server.New(server.Options{Addr: "127.0.0.1:0", Clock: testClock()})
	if err != nil {
		t.Fatalf("server.New() = %v", err)
	}
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if _, err := http.Get("http://" + srv.Addr() + server.HealthPath); err == nil {
		t.Error("the listener still answers after Shutdown")
	}
}

func TestNewRejectsEmptyAddr(t *testing.T) {
	t.Parallel()

	if _, err := server.New(server.Options{}); err == nil {
		t.Fatal("server.New() accepted an empty listen address")
	}
}

func TestAddrReportsBoundPort(t *testing.T) {
	t.Parallel()

	srv, _ := start(t, server.Options{Addr: "127.0.0.1:0"})
	if addr := srv.Addr(); strings.HasSuffix(addr, ":0") || !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("Addr() = %q, want the bound loopback port", addr)
	}
}

// shutdown stops srv with a deadline of its own: t.Context is already
// cancelled by the time cleanup functions run.
func shutdown(t *testing.T, srv *server.Server) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() = %v", err)
	}
}

func certPool(t *testing.T, certFile string) *x509.CertPool {
	t.Helper()

	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the generated certificate is not a usable trust anchor")
	}
	return pool
}

func httpsClient(t *testing.T, certFile string) *http.Client {
	t.Helper()

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: certPool(t, certFile), MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}
