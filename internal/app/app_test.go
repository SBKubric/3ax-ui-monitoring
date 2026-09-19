package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
