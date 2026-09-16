package registry

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// AuthenticateClient resolves the bearer token of an authenticated /v1 call to
// the mon-client that owns it (mon-protocol.md §3). It implements
// api.Authenticator.
//
// The token is hashed and the hash is looked up; the stored hash is then
// compared constant-time, so that a lookup which matched on something other
// than the full value — a prefix index, a future migration — cannot let a
// near-miss through. A revoked mon-client has a blank token_hash and can never
// be matched, not even by an empty bearer token, whose hash is a real
// SHA-256 and never blank.
func (r *Registry) AuthenticateClient(ctx context.Context, token string) (api.Identity, error) {
	if token == "" {
		return api.Identity{}, api.ErrTokenRevoked
	}
	hash := store.HashToken(token)
	var mc store.MonClient
	err := r.st.DB().WithContext(ctx).
		Where("token_hash = ? AND token_hash <> ''", hash).
		Take(&mc).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return api.Identity{}, api.ErrTokenRevoked
	case err != nil:
		return api.Identity{}, fmt.Errorf("registry: look up client token: %w", err)
	}
	if mc.TokenHash == "" || subtle.ConstantTimeCompare([]byte(mc.TokenHash), []byte(hash)) != 1 {
		return api.Identity{}, api.ErrTokenRevoked
	}
	if !mc.Enabled {
		return api.Identity{}, api.ErrClientDisabled
	}
	return api.Identity{MonClientID: mc.ID}, nil
}
