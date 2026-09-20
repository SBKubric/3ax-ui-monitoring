package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// stubAuthenticator is a scriptable stand-in for *registry.Registry so this
// package's middleware tests don't need a real database — they only need to
// check how RequireClientToken reacts to each of Authenticate's possible
// outcomes.
type stubAuthenticator struct {
	client *store.MonClient
	err    error
}

func (s stubAuthenticator) Authenticate(context.Context, string) (*store.MonClient, error) {
	return s.client, s.err
}

func newAuthTestServer(auth stubAuthenticator) (*Server, string) {
	s := New()
	const relPath = "/probe-protected"
	s.V1.GET(relPath, RequireClientToken(auth), func(c *gin.Context) {
		mc := MonClientFrom(c)
		if mc == nil {
			c.String(http.StatusInternalServerError, "no mon-client in context")
			return
		}
		c.String(http.StatusOK, mc.Id)
	})
	return s, "/v1" + relPath
}

// TestRequireClientToken_MissingHeader checks that a request with no
// Authorization header at all gets 401 token_revoked — protocol §3 has no
// third code for "no token presented".
func TestRequireClientToken_MissingHeader(t *testing.T) {
	s, path := newAuthTestServer(stubAuthenticator{err: registry.ErrTokenRevoked})

	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}
}

// TestRequireClientToken_GarbageHeader checks that a header that isn't
// "Bearer <token>" at all (wrong scheme, or empty token) is also 401
// without ever reaching Authenticate.
func TestRequireClientToken_GarbageHeader(t *testing.T) {
	cases := []string{"garbage", "Basic dXNlcjpwYXNz", "Bearer "}
	for _, h := range cases {
		s, path := newAuthTestServer(stubAuthenticator{err: registry.ErrTokenRevoked})
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", h)
		rec := httptest.NewRecorder()
		s.Engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401, body=%s", h, rec.Code, rec.Body.String())
		}
	}
}

// TestRequireClientToken_AuthenticateOutcomes checks how RequireClientToken
// maps each of Authenticate's possible outcomes to a response — success and
// both known sentinel errors — as one table, since the three cases only
// differ in the stubbed outcome and the expected status/body (testing.md:
// "table-driven where cases repeat").
func TestRequireClientToken_AuthenticateOutcomes(t *testing.T) {
	mc := &store.MonClient{Id: "ams-1"}
	cases := []struct {
		name       string
		stub       stubAuthenticator
		wantStatus int
		wantBody   string
	}{
		{"valid token reaches the handler", stubAuthenticator{client: mc}, http.StatusOK, "ams-1"},
		{"token revoked is 401", stubAuthenticator{err: registry.ErrTokenRevoked}, http.StatusUnauthorized, `"error":"token_revoked"`},
		{"disabled is 403", stubAuthenticator{err: registry.ErrDisabled}, http.StatusForbidden, `"error":"disabled"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, path := newAuthTestServer(tc.stub)

			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer some-token")
			rec := httptest.NewRecorder()
			s.Engine.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body = %q, want substring %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestRequireClientToken_InternalErrorDoesNotLeakDetails checks that a
// non-sentinel error from Authenticate (a DB failure) never reaches the
// response body — driver detail like a sqlite busy/locked message has no
// business reaching an unauthenticated caller. It is logged instead, and
// the caller gets a generic 500.
func TestRequireClientToken_InternalErrorDoesNotLeakDetails(t *testing.T) {
	dbErr := fmt.Errorf("authenticate: %w", errors.New("database is locked (5) (SQLITE_BUSY)"))
	s, path := newAuthTestServer(stubAuthenticator{err: dbErr})

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	s.Engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "SQLITE_BUSY") || strings.Contains(rec.Body.String(), "database is locked") {
		t.Fatalf("body = %q, leaked internal error detail", rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got["error"] != "internal" || got["message"] != "internal error" {
		t.Fatalf("body = %v, want {error: internal, message: internal error}", got)
	}
}
