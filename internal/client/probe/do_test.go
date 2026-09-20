package probe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// Do is tested without a tunnel — a plain loopback server is enough for the
// request's own shape (protocol §5.2) — while the tunnelled paths live in
// xray_test.go. Step 6's AWG probe reuses exactly this function.

func TestDo_SendsTargetNonceAndToken(t *testing.T) {
	var gotTarget, gotNonce, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTarget = r.URL.Query().Get("target")
		gotNonce = r.URL.Query().Get("n")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(proto.ProbeEcho{Nonce: gotNonce, EgressIp: "203.0.113.7", ServerTs: 7})
	}))
	defer srv.Close()

	ph, echo, err := Do(context.Background(), &http.Transport{}, srv.URL+"/v1/probe", testToken, testKey, fastBudgets())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotTarget != "xray:12:proxy" {
		t.Errorf("target = %q, want the key's wire form", gotTarget)
	}
	if len(gotNonce) < 20 { // 16 raw bytes base64url = 22 characters
		t.Errorf("nonce = %q, want 16 random bytes base64url", gotNonce)
	}
	if gotAuth != "Bearer "+testToken {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if echo.EgressIp != "203.0.113.7" {
		t.Errorf("egressIp = %q", echo.EgressIp)
	}
	if ph.ConnectMs == nil || ph.TtfbMs == nil {
		t.Errorf("phases: connect=%v ttfb=%v", ph.ConnectMs, ph.TtfbMs)
	}
	if ph.TlsMs != nil {
		t.Errorf("tlsMs = %d over a plaintext server", *ph.TlsMs)
	}
}

func TestDo_NonceMismatchAndStatusAreTyped(t *testing.T) {
	var status int
	var echoNonce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"token_revoked","message":"no"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(proto.ProbeEcho{Nonce: echoNonce})
	}))
	defer srv.Close()

	echoNonce = "someone-elses-nonce"
	_, _, err := Do(context.Background(), &http.Transport{}, srv.URL, testToken, testKey, fastBudgets())
	var mismatch *NonceMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v (%T), want *NonceMismatchError", err, err)
	}
	if mismatch.Got != echoNonce || mismatch.Want == "" {
		t.Errorf("mismatch = %+v", mismatch)
	}

	status = http.StatusUnauthorized
	_, _, err = Do(context.Background(), &http.Transport{}, srv.URL, testToken, testKey, fastBudgets())
	var se *HTTPStatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *HTTPStatusError", err, err)
	}
	if se.Status != http.StatusUnauthorized || !strings.Contains(se.Body, "token_revoked") {
		t.Errorf("status error = %+v", se)
	}
}

func TestDo_BodyInStatusErrorIsTrimmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("я", 1000)))
	}))
	defer srv.Close()

	_, _, err := Do(context.Background(), &http.Transport{}, srv.URL, testToken, testKey, fastBudgets())
	var se *HTTPStatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *HTTPStatusError", err)
	}
	if n := len([]rune(se.Body)); n != MaxDetail {
		t.Errorf("body is %d runes, want %d (protocol §5.3)", n, MaxDetail)
	}
}

func TestDo_AppliesBudgetsToTheTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(proto.ProbeEcho{Nonce: r.URL.Query().Get("n")})
	}))
	defer srv.Close()

	tr := &http.Transport{}
	b := Budgets{Budget: 2 * time.Second, Connect: 700 * time.Millisecond, TLS: 800 * time.Millisecond, Headers: 900 * time.Millisecond}
	if _, _, err := Do(context.Background(), tr, srv.URL, testToken, testKey, b); err != nil {
		t.Fatalf("Do: %v", err)
	}
	// Spec §5: a probe never reuses a connection, or it would have no
	// connect/TLS phase to report at all (research §5).
	if !tr.DisableKeepAlives {
		t.Error("DisableKeepAlives not set")
	}
	if tr.TLSHandshakeTimeout != b.TLS || tr.ResponseHeaderTimeout != b.Headers {
		t.Errorf("timeouts = tls %v headers %v, want %v / %v", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, b.TLS, b.Headers)
	}
	if tr.DialContext == nil {
		t.Error("DialContext not set, so the connect budget is not applied")
	}
}
