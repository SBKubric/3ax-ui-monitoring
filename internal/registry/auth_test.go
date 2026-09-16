package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

func TestAuthenticateClient(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()

	// One working mon-client, one disabled, one whose token was revoked.
	live := submit(t, reg, "203.0.113.1", "7K3F9Q")
	approve(t, reg, live.RequestID, ApproveInput{Name: "ams 1"})
	liveToken := issuedToken(t, reg, live.RequestID)

	fake.Advance(61 * time.Second) // so the next box may file its request
	off := submit(t, reg, "203.0.113.2", "7K3F9Q")
	approve(t, reg, off.RequestID, ApproveInput{Name: "fra 1"})
	offToken := issuedToken(t, reg, off.RequestID)
	if err := reg.Disable(ctx, "fra-1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	fake.Advance(61 * time.Second)
	gone := submit(t, reg, "203.0.113.3", "7K3F9Q")
	approve(t, reg, gone.RequestID, ApproveInput{Name: "msk 1"})
	goneToken := issuedToken(t, reg, gone.RequestID)
	if err := reg.Revoke(ctx, "msk-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	tests := []struct {
		name    string
		token   string
		wantID  string
		wantErr error
	}{
		{name: "a live token names its mon-client", token: liveToken, wantID: "ams-1"},
		{name: "an unknown token is revoked", token: "not-a-token", wantErr: api.ErrTokenRevoked},
		{name: "an empty token is revoked", token: "", wantErr: api.ErrTokenRevoked},
		{name: "a token that only differs in case is revoked", token: flipCase(liveToken), wantErr: api.ErrTokenRevoked},
		{name: "a hash presented as a token is revoked", token: store.HashToken(liveToken), wantErr: api.ErrTokenRevoked},
		{name: "a revoked token is revoked", token: goneToken, wantErr: api.ErrTokenRevoked},
		{name: "a disabled mon-client is disabled, not revoked", token: offToken, wantErr: api.ErrClientDisabled},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := reg.AuthenticateClient(ctx, tc.token)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("AuthenticateClient = %v, %v, want %v", id, err, tc.wantErr)
				}
				if id.MonClientID != "" {
					t.Errorf("a refused token still named %q", id.MonClientID)
				}
				return
			}
			if err != nil {
				t.Fatalf("AuthenticateClient: %v", err)
			}
			if id.MonClientID != tc.wantID {
				t.Errorf("identity = %q, want %q", id.MonClientID, tc.wantID)
			}
		})
	}

	// The revoked row is still there, with nothing to match against.
	if got := clientRow(t, st, "msk-1").TokenHash; got != "" {
		t.Errorf("token_hash of a revoked mon-client = %q, want it blank", got)
	}
}

func TestAuthenticateClientNeverMatchesABlankStoredHash(t *testing.T) {
	reg, st, _ := newTestRegistry(t)
	ctx := context.Background()

	// A registry holding nothing but revoked rows: no token may pass, and
	// least of all the empty one, whose hash is a real SHA-256 anyway.
	rows := []store.MonClient{
		{ID: "ams-1", Name: "AMS 1", State: store.ClientStateOffline, Enabled: true},
		{ID: "fra-1", Name: "FRA 1", State: store.ClientStateOffline, Enabled: true},
	}
	if err := st.DB().Create(&rows).Error; err != nil {
		t.Fatalf("create revoked mon-clients: %v", err)
	}

	for _, token := range []string{"", " ", store.HashToken(""), "\x00"} {
		id, err := reg.AuthenticateClient(ctx, token)
		if !errors.Is(err, api.ErrTokenRevoked) {
			t.Errorf("AuthenticateClient(%q) = %v, %v, want ErrTokenRevoked", token, id, err)
		}
	}
}

// flipCase swaps the case of every letter, producing a token of the same shape
// that must not authenticate.
func flipCase(token string) string {
	out := []rune(token)
	for i, ru := range out {
		switch {
		case ru >= 'a' && ru <= 'z':
			out[i] = ru - 'a' + 'A'
		case ru >= 'A' && ru <= 'Z':
			out[i] = ru - 'A' + 'a'
		}
	}
	return string(out)
}
