package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx/tlsxtest"
)

// newTestApp builds an App in "files" TLS mode against a fresh self-signed
// cert and a fresh temp-file store, listening on an OS-assigned loopback
// port. It registers t.Cleanup to shut the App down so no test leaks a
// goroutine into the next one under -race.
func newTestApp(t *testing.T) (*App, *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)

	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	cfg := &config.Config{
		Listen:  "127.0.0.1:0",
		DataDir: dir,
		TLS:     config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}

	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: tg.Nop{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}

	return a, &tls.Config{RootCAs: pool}
}

// TestStartAndHealthz checks the "files" mode happy path the issue's test
// list names: the listener comes up and answers /healthz over real TLS
// trusted only because the client was handed this specific self-signed
// cert — proving Start actually serves the tls.Config tlsx.Build produced,
// not some other listener.
func TestStartAndHealthz(t *testing.T) {
	a, clientTLS := newTestApp(t)

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestShutdown_WaitsForInFlightRequest checks the graceful-shutdown
// requirement (spec §2): Shutdown must not return while a handler is still
// running, and the in-flight request must still complete successfully
// rather than being cut off.
func TestShutdown_WaitsForInFlightRequest(t *testing.T) {
	a, clientTLS := newTestApp(t)

	release := make(chan struct{})
	handlerStarted := make(chan struct{})
	a.Server().Engine.GET("/block", func(c *gin.Context) {
		close(handlerStarted)
		<-release
		c.String(http.StatusOK, "done")
	})

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}

	type result struct {
		status int
		err    error
	}
	reqDone := make(chan result, 1)
	go func() {
		resp, err := client.Get("https://" + addr + "/block")
		if err != nil {
			reqDone <- result{err: err}
			return
		}
		defer resp.Body.Close()
		reqDone <- result{status: resp.StatusCode}
	}()

	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked handler never started")
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- a.Shutdown(ctx)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned before the in-flight request finished")
	case <-time.After(200 * time.Millisecond):
		// expected: Shutdown is still waiting on /block.
	}

	close(release)

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the handler was released")
	}

	res := <-reqDone
	if res.err != nil {
		t.Fatalf("in-flight request failed: %v", res.err)
	}
	if res.status != http.StatusOK {
		t.Fatalf("in-flight request status = %d, want 200", res.status)
	}
}

// TestShutdown_ReturnsPromptlyWithNoRequests checks that Shutdown does not
// itself impose any delay when there is nothing to wait for — it must not,
// say, always block for the full grace period.
func TestShutdown_ReturnsPromptlyWithNoRequests(t *testing.T) {
	a, _ := newTestApp(t)
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Shutdown took %v with no in-flight requests, want well under 1s", elapsed)
	}
}

// TestRun_ShutsDownWhenContextCancelled checks the top-level lifecycle
// cmd/mon-server drives: Run blocks while ctx is live and returns once it is
// cancelled, after shutting the listener down. Start/Shutdown themselves are
// covered above; this only needs to prove Run wires ctx cancellation to
// shutdown and returns.
func TestRun_ShutsDownWhenContextCancelled(t *testing.T) {
	a, _ := newTestApp(t)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Give Run's Start() a moment to happen before cancelling; Run logs
	// "listening" synchronously right after Start returns, so a short,
	// generous sleep is enough without needing to observe the address.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx was cancelled")
	}
}

// TestRun_ReturnsErrorWhenAcceptLoopDiesUnexpectedly checks that Run does
// not park forever on <-ctx.Done() when the server has already stopped
// serving for a reason other than Shutdown (here: its listener fd closed
// out from under it). Run must notice via serveErrCh and return a non-nil
// error promptly instead of hanging until the test's own context is ever
// cancelled (in production: until the process is killed, serving nothing).
func TestRun_ReturnsErrorWhenAcceptLoopDiesUnexpectedly(t *testing.T) {
	a, _ := newTestApp(t)

	// Never cancelled by this test: if Run were to (incorrectly) only
	// watch ctx.Done(), it would hang until the 5s select below times out,
	// which is exactly the failure mode this test exists to catch.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Wait for Run's Start() to publish the bound listener on lnCh (a
	// synchronized handoff — reading a.ln directly here would race Start's
	// write to it) before reaching in — this test is in-package precisely
	// so it can — and closing it out from under the server, simulating a
	// dead accept loop.
	var ln net.Listener
	select {
	case ln = <-a.lnCh:
	case <-time.After(5 * time.Second):
		t.Fatal("listener was never bound")
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener out from under the server: %v", err)
	}

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("Run: want a non-nil error when the accept loop dies unexpectedly, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after the listener died out from under it")
	}
}

// TestApp_ReadTimeoutClosesStalledBody checks the public-listener timeout
// fix: a client that sends a request's headers (with a Content-Length
// promising a body) and then never sends that body must be disconnected
// within the configured read timeout, not left tying up a handler
// goroutine indefinitely. It uses newApp's unexported timeout override so
// the test runs in milliseconds instead of sleeping for the real 30s
// production value.
func TestApp_ReadTimeoutClosesStalledBody(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)

	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	cfg := &config.Config{
		Listen:  "127.0.0.1:0",
		DataDir: dir,
		TLS:     config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}

	const shortReadTimeout = 300 * time.Millisecond
	a, err := newApp(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: tg.Nop{}}, shortReadTimeout, writeTimeout)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	a.Server().Engine.POST("/upload", func(c *gin.Context) {
		_, _ = io.Copy(io.Discard, c.Request.Body)
		c.Status(http.StatusOK)
	})

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse test cert")
	}

	// pr is a body that promises 10 bytes (ContentLength below) but never
	// delivers any: the handler's io.Copy blocks reading from it exactly
	// like it would block reading a real mon-client connection that sent
	// headers and then stalled.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })

	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/upload", pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = 10

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	start := time.Now()
	respCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		respCh <- err
	}()

	// Whether the round trip ends in an error (connection reset/closed
	// while the client was still trying to deliver the body) or in a
	// response (the server gave up reading the body and replied anyway),
	// what matters is that it happens promptly: readTimeout must actually
	// bound the wait, instead of the handler's io.Copy blocking forever on
	// a body that never arrives.
	select {
	case <-respCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("client.Do did not return within 2s of a %v read timeout — the server appears to be blocked waiting for the stalled body", shortReadTimeout)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("round trip with a stalled body took %v, want well under 1.5s (readTimeout=%v)", elapsed, shortReadTimeout)
	}
}

// TestShutdown_JoinsThePanelPoller checks that the panel poll loop (spec §4)
// is started by Start and actually joined by Shutdown: a goroutine still
// running after Shutdown returned would keep writing to a database the
// process believes it has closed, and would show up as a leak under -race.
func TestShutdown_JoinsThePanelPoller(t *testing.T) {
	a, _ := newTestApp(t)

	if a.Poller() == nil {
		t.Fatal("New did not wire a panel poller")
	}
	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !a.pollStopped.Load() {
		t.Fatal("Shutdown returned while the panel poll loop was still running")
	}
	if a.Poller().PanelDown() {
		t.Fatal("an unconfigured mon-server must not start out in PANEL_DOWN")
	}
}

// hangingNotifier is a tg.Notifier that ignores ctx entirely and blocks
// until released — standing in for a collaborator that does not honour
// cancellation as diligently as the panel HTTPClient does (plausible for the
// real Telegram client's own HTTP call, step 9's problem to get right, not
// this one's). It is what makes TestShutdown_AbandonsAHungPollerWhenItsCtxExpires
// a genuine reproduction: the panel HTTPClient's request-scoped cancellation
// alone cannot be relied on to unstick every cycle promptly.
type hangingNotifier struct{ release chan struct{} }

func (h *hangingNotifier) Send(context.Context, string) error {
	<-h.release
	return nil
}

// TestShutdown_AbandonsAHungPollerWhenItsCtxExpires checks the self-check
// finding on Shutdown's other lifecycle point: joining the panel poll loop
// must be bounded by Shutdown's own ctx, not by however long the poller
// actually takes to return. A cycle stuck inside a collaborator that does
// not honour ctx cancellation must not be able to keep Shutdown from ever
// returning — it comes back once its own ctx expires, having abandoned the
// still-running poller rather than waited on it forever. Without the bound
// this reproduces the old bug: Shutdown would hang until the notifier is
// released, however long that takes.
func TestShutdown_AbandonsAHungPollerWhenItsCtxExpires(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := tlsxtest.WriteSelfSigned(t, dir)
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	notifier := &hangingNotifier{release: make(chan struct{})}

	cfg := &config.Config{
		Listen:  "127.0.0.1:0",
		DataDir: dir,
		TLS:     config.TLSConfig{Mode: config.TLSModeFiles, Cert: certPath, Key: keyPath},
	}
	a, err := New(Deps{Cfg: cfg, Store: st, Clock: clock.Real{}, Notifier: notifier})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Shutdown(ctx)
	})
	// Registered after the Shutdown cleanup above, so t.Cleanup's LIFO order
	// runs this first: unblock the notifier before that final Shutdown call
	// has to abandon it a second time, so the goroutine this test
	// intentionally stalls does not leak into the rest of the test binary's
	// life.
	t.Cleanup(func() { close(notifier.release) })

	stub := paneltest.NewStub(t)
	stub.SetMonEnabled(false) // bare 404 on every request (contract §2)

	set := store.DefaultSettings()
	set.PanelURL = stub.URL()
	set.MonToken = stub.Token()
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	if _, err := a.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The first cycle runs immediately (no minute-long wait needed): the
	// bare 404 fires notifyRejected on its very first Poll, which is where
	// the poll loop is now stuck inside notifier.Send.
	time.Sleep(150 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := a.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Shutdown took %v, want to return once its own ctx expired rather than wait forever on the stuck notifier", elapsed)
	}
	if a.pollStopped.Load() {
		t.Fatal("the poll loop is reported stopped, but its notifier is still blocked — the test's own premise is broken")
	}
}

// TestRegistry_WiredIntoServer checks step 4's wiring: New builds a
// non-nil Registry, exposed through App.Registry, and the same instance
// backs the POST /v1/register route New mounted on Server().V1 — a real
// registration request over the App's own TLS listener gets the protocol's
// 202, not the JSON error envelope's "no such route".
func TestRegistry_WiredIntoServer(t *testing.T) {
	a, clientTLS := newTestApp(t)
	if a.Registry() == nil {
		t.Fatal("Registry() = nil, want a constructed *registry.Registry")
	}

	addr, err := a.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	body := bytes.NewBufferString(`{"pairingCode":"ABCDEF","hostname":"h","version":"0.1.0","publicIp":"203.0.113.5"}`)
	resp, err := client.Post("https://"+addr+"/v1/register", "application/json", body)
	if err != nil {
		t.Fatalf("POST /v1/register: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
}
