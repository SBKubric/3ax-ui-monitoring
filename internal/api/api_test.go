package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestNew_Healthz checks the one route spec §10 says needs no
// authentication at all: a bare 200 with body "ok".
func TestNew_Healthz(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

// TestNew_HeadHealthz checks that HEAD is registered alongside GET on
// /healthz, for uptime monitors and load balancers that probe liveness with
// HEAD to avoid pulling a response body they discard anyway.
func TestNew_HeadHealthz(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "/healthz", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestNew_V1NoRouteIsProtocolError checks that an unmatched /v1/* path gets
// the mon-client protocol's JSON error envelope, not gin's default plain
// 404, so mon-clients always get a body they can parse.
func TestNew_V1NoRouteIsProtocolError(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/nope", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if !strings.Contains(rec.Body.String(), `"error":"not_found"`) {
		t.Fatalf("body = %q, want it to contain the not_found error code", rec.Body.String())
	}
}

// TestNew_BareV1NoRouteIsProtocolError checks that "/v1" with no trailing
// slash also gets the protocol's JSON error envelope, not gin's default
// plain 404 — a mon-client (or a test) that requests the bare group path
// must not fall through to the non-/v1 branch just because it's missing a
// slash.
func TestNew_BareV1NoRouteIsProtocolError(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"not_found"`) {
		t.Fatalf("body = %q, want it to contain the not_found error code", rec.Body.String())
	}
}

// TestNew_NonV1NoRouteIsPlain404 checks that the JSON error envelope is
// scoped to /v1 only: a miss anywhere else (e.g. under /admin, which gets
// its own 404 page in step 10) keeps gin's default behaviour instead.
func TestNew_NonV1NoRouteIsPlain404(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nope", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("body = %q, want it NOT to be the /v1 protocol error envelope", rec.Body.String())
	}
}

// TestFail_SetsStatusBodyAndAborts checks the shared error helper every
// later step's handlers use: the exact status, the protocol's {error,
// message} body, and that the context is aborted so no later handler in the
// chain runs.
func TestFail_SetsStatusBodyAndAborts(t *testing.T) {
	s := New()
	secondRan := false
	s.V1.GET("/boom",
		func(c *gin.Context) { Fail(c, http.StatusForbidden, "disabled", "client is disabled") },
		func(c *gin.Context) { secondRan = true },
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/boom", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"disabled"`) || !strings.Contains(rec.Body.String(), `"message":"client is disabled"`) {
		t.Fatalf("body = %q, want the disabled error envelope", rec.Body.String())
	}
	if secondRan {
		t.Fatal("a handler after Fail ran: want the chain aborted")
	}
}

// TestNew_PanicIsLoggedWith500 checks the middleware order fix: a handler
// that panics must still produce a structured slog line recording status
// 500, not just gin.Recovery()'s own 500 response with no log line at all
// (which is what registering Recovery before requestLogger would do, since
// the panic would then unwind past requestLogger's post-c.Next() logging
// code before Recovery ever got a chance to stop it).
func TestNew_PanicIsLoggedWith500(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := New()
	s.Engine.GET("/panic", func(c *gin.Context) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	log := buf.String()
	if !strings.Contains(log, "http request") {
		t.Fatalf("log = %q, want a request log line for the panicking handler", log)
	}
	if !strings.Contains(log, "status=500") {
		t.Fatalf("log = %q, want it to record status=500", log)
	}
}

// TestNew_TrustedProxiesDisabled_XForwardedForIsIgnored checks the security
// fix: mon-server terminates TLS itself with no reverse proxy in front of
// it, so X-Forwarded-For must never be honoured — otherwise any client could
// spoof c.ClientIP() and bypass a per-IP rate limit (step 4).
func TestNew_TrustedProxiesDisabled_XForwardedForIsIgnored(t *testing.T) {
	s := New()
	var gotIP string
	s.Engine.GET("/whoami", func(c *gin.Context) {
		gotIP = c.ClientIP()
		c.Status(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.RemoteAddr = "192.0.2.1:12345"
	s.Engine.ServeHTTP(rec, req)

	if gotIP == "1.2.3.4" {
		t.Fatalf("ClientIP() = %q, want the socket peer, not a spoofed X-Forwarded-For", gotIP)
	}
	if gotIP != "192.0.2.1" {
		t.Fatalf("ClientIP() = %q, want %q (the socket peer)", gotIP, "192.0.2.1")
	}
}
