package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// newTestServer starts an httptest server whose every response is decided
// by handler, and returns a Client pointed at it.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(srv.URL, srv.Client()), srv
}

func writeErrBody(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

// TestClient_ErrorMapping drives the whole architecture brief §1 mapping
// table through Config (an authenticated GET) against a stub server that
// answers exactly one status per case.
func TestClient_ErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		retryAfter string
		checkErr   func(t *testing.T, err error)
	}{
		{
			name: "401 token revoked", status: http.StatusUnauthorized,
			checkErr: func(t *testing.T, err error) {
				if !errors.Is(err, ErrTokenRevoked) {
					t.Fatalf("err = %v, want ErrTokenRevoked", err)
				}
			},
		},
		{
			name: "403 disabled", status: http.StatusForbidden,
			checkErr: func(t *testing.T, err error) {
				if !errors.Is(err, ErrDisabled) {
					t.Fatalf("err = %v, want ErrDisabled", err)
				}
			},
		},
		{
			name: "410 request expired", status: http.StatusGone,
			checkErr: func(t *testing.T, err error) {
				if !errors.Is(err, ErrRequestExpired) {
					t.Fatalf("err = %v, want ErrRequestExpired", err)
				}
			},
		},
		{
			name: "429 with Retry-After", status: http.StatusTooManyRequests, retryAfter: "17",
			checkErr: func(t *testing.T, err error) {
				var rl *RateLimitError
				if !errors.As(err, &rl) {
					t.Fatalf("err = %v (%T), want *RateLimitError", err, err)
				}
				if rl.RetryAfter != 17*time.Second {
					t.Fatalf("RetryAfter = %s, want 17s", rl.RetryAfter)
				}
			},
		},
		{
			name: "503 config not ready", status: http.StatusServiceUnavailable,
			checkErr: func(t *testing.T, err error) {
				var se *StatusError
				if !errors.As(err, &se) {
					t.Fatalf("err = %v (%T), want *StatusError", err, err)
				}
				if se.Status != http.StatusServiceUnavailable || se.Code != "config_not_ready" {
					t.Fatalf("StatusError = %+v, want 503 config_not_ready", se)
				}
			},
		},
		{
			name: "500 internal", status: http.StatusInternalServerError,
			checkErr: func(t *testing.T, err error) {
				var se *StatusError
				if !errors.As(err, &se) {
					t.Fatalf("err = %v (%T), want *StatusError", err, err)
				}
				if se.Status != http.StatusInternalServerError {
					t.Fatalf("StatusError.Status = %d, want 500", se.Status)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				code := "injected"
				if tc.status == http.StatusServiceUnavailable {
					code = "config_not_ready"
				}
				writeErrBody(w, tc.status, code, "injected failure")
			})
			_, err := client.Config(context.Background())
			if err == nil {
				t.Fatalf("Config() error = nil, want an error")
			}
			tc.checkErr(t, err)
		})
	}
}

// TestClient_TransportError checks a connection that never completes (a
// closed listener) maps to *NetError, distinct from every HTTP-status
// case above.
func TestClient_TransportError(t *testing.T) {
	// A listener that is immediately closed still reserves a real address
	// nothing answers on, which is a reliable way to make Dial fail without
	// depending on any particular unused port being free.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	client := New("http://"+addr, &http.Client{})
	_, err = client.Config(context.Background())
	var netErr *NetError
	if !errors.As(err, &netErr) {
		t.Fatalf("err = %v (%T), want *NetError", err, err)
	}
	if netErr.Op != "config" {
		t.Fatalf("NetError.Op = %q, want %q", netErr.Op, "config")
	}
}

// TestClient_Timeout checks a server that never responds within the
// caller's context deadline maps to *NetError whose Timeout() is true —
// what the registration backoff (step 2) and the heartbeat loop (step 7)
// both need to tell "server is slow" apart from "server said no".
func TestClient_Timeout(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.Config(ctx)

	var netErr *NetError
	if !errors.As(err, &netErr) {
		t.Fatalf("err = %v (%T), want *NetError", err, err)
	}
	if !netErr.Timeout() {
		t.Fatalf("NetError.Timeout() = false, want true")
	}
}

// TestClient_UnknownFieldsTolerated checks that a response body carrying
// fields this package's proto types do not know about still decodes
// (protocol §1: both sides must tolerate unknown fields).
func TestClient_UnknownFieldsTolerated(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"configRevision":"abc123","monClientId":"ams-1","probeUrl":"https://x/v1/probe","probe":{"intervalMs":60000},"targets":[],"future":{"nested":true}}`))
	})
	doc, err := client.Config(context.Background())
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if doc.ConfigRevision != "abc123" || doc.MonClientID != "ams-1" {
		t.Fatalf("doc = %+v, unexpected", doc)
	}
}

// TestClient_RegisterAndPollHappyPath exercises Register/Poll's success
// shapes against protocol §2.1/§2.2's own field names, and confirms neither
// call sends an Authorization header (a mon-client has no token yet at
// this point in its life).
func TestClient_RegisterAndPollHappyPath(t *testing.T) {
	var sawAuthOnRegister, sawAuthOnPoll bool
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/register":
			sawAuthOnRegister = r.Header.Get("Authorization") != ""
			var body proto.RegisterRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.PairingCode != "7K3F9Q" {
				t.Errorf("PairingCode = %q, want 7K3F9Q", body.PairingCode)
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(proto.RegisterResponse{RequestID: "req-1", PollAfterMs: 10000, ExpiresAt: 123})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/register/req-1":
			sawAuthOnPoll = r.Header.Get("Authorization") != ""
			_ = json.NewEncoder(w).Encode(proto.PollResponse{Status: "approved", MonClientID: "ams-1", Token: "tok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	reg, err := client.Register(context.Background(), proto.RegisterRequest{PairingCode: "7K3F9Q", Hostname: "vps-1", Version: "0.1.0"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.RequestID != "req-1" || reg.PollAfterMs != 10000 {
		t.Fatalf("RegisterResponse = %+v", reg)
	}
	if sawAuthOnRegister {
		t.Fatalf("Register sent an Authorization header")
	}

	poll, err := client.Poll(context.Background(), reg.RequestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if poll.Status != "approved" || poll.MonClientID != "ams-1" || poll.Token != "tok" {
		t.Fatalf("PollResponse = %+v", poll)
	}
	if sawAuthOnPoll {
		t.Fatalf("Poll sent an Authorization header")
	}
}

// TestClient_HeartbeatSendsBearerToken checks Heartbeat authenticates with
// the configured token (protocol §3) and round-trips the ackSeq field.
func TestClient_HeartbeatSendsBearerToken(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization = %q, want Bearer tok-123", got)
		}
		_ = json.NewEncoder(w).Encode(proto.HeartbeatResponse{ConfigRevision: "rev", ServerTs: 1, AckSeq: 42})
	})
	client.Token = "tok-123"

	resp, err := client.Heartbeat(context.Background(), &proto.HeartbeatRequest{MonClientID: "ams-1"})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if resp.AckSeq != 42 {
		t.Fatalf("AckSeq = %d, want 42", resp.AckSeq)
	}
}

// TestNew_IgnoresEnvironmentProxy pins spec §6's "свой Transport без
// прокси": a box whose HTTP(S)_PROXY points at something dead (here a
// loopback port with nothing behind it — the shape of a misconfigured or
// tunnel-local proxy on a real VPS) must still reach mon-server directly.
// A zero-value *http.Client would use http.DefaultTransport, which reads
// those variables, so this is a test of what New builds, not of net/http.
func TestNew_IgnoresEnvironmentProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(proto.RegisterResponse{RequestID: "req-1", PollAfterMs: 10000})
	}))
	defer srv.Close()

	// A closed loopback port: any request routed through it fails.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxyURL := "http://" + dead.Addr().String()
	if err := dead.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Setenv("HTTP_PROXY", proxyURL)
	t.Setenv("HTTPS_PROXY", proxyURL)
	t.Setenv("http_proxy", proxyURL)
	t.Setenv("https_proxy", proxyURL)

	c := New(srv.URL, nil)
	resp, err := c.Register(context.Background(), proto.RegisterRequest{PairingCode: "ABC234"})
	if err != nil {
		t.Fatalf("Register through a proxy-free transport: %v", err)
	}
	if resp.RequestID != "req-1" {
		t.Fatalf("requestId = %q, want req-1", resp.RequestID)
	}
}

// TestNew_KeepsCallerTransport checks the other half of New's contract: a
// caller that brought its own transport (servertest's, trusting its own
// certificate) keeps it.
func TestNew_KeepsCallerTransport(t *testing.T) {
	tr := &http.Transport{}
	c := New("https://example.invalid", &http.Client{Transport: tr})
	if c.HTTP.Transport != tr {
		t.Fatalf("transport = %#v, want the caller's own", c.HTTP.Transport)
	}
}
