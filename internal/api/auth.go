package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// monClientContextKey is the gin context key RequireClientToken stashes the
// authenticated *store.MonClient under, and MonClientFrom reads it back
// from. Unexported so the only way to reach it is through those two
// functions — a handler can never accidentally read a stale or
// wrongly-typed value under a guessed string key.
const monClientContextKey = "monClient"

// RequireClientToken is the gin middleware every `/v1/*` handler except
// `/v1/register*` runs behind (protocol §3): it demands `Authorization:
// Bearer <token>`, authenticates it against auth (satisfied by
// *registry.Registry in production; a stub in this package's own tests),
// and on success stashes the resolved mon-client for MonClientFrom. A
// missing or malformed header gets the same 401 token_revoked as an unknown
// token — protocol §3 defines only two auth failure codes, and a mon-client
// cannot tell "I sent no header" from "my token is wrong" apart anyway, so
// there is no third code to invent.
func RequireClientToken(auth interface {
	Authenticate(context.Context, string) (*store.MonClient, error)
}) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok || token == "" {
			Fail(c, http.StatusUnauthorized, "token_revoked", "missing or malformed Authorization header")
			return
		}

		mc, err := auth.Authenticate(c.Request.Context(), token)
		switch {
		case err == nil:
			c.Set(monClientContextKey, mc)
			c.Next()
		case errors.Is(err, registry.ErrTokenRevoked):
			Fail(c, http.StatusUnauthorized, "token_revoked", err.Error())
		case errors.Is(err, registry.ErrDisabled):
			Fail(c, http.StatusForbidden, "disabled", err.Error())
		default:
			// A non-sentinel error here is Authenticate's own DB call
			// failing (e.g. sqlite busy/locked) — its Error() text can
			// carry driver detail that has no business reaching an
			// unauthenticated caller, so it goes to the log instead and the
			// response says nothing more than "internal error".
			slog.Error("auth: internal error", "error", err)
			Fail(c, http.StatusInternalServerError, "internal", "internal error")
		}
	}
}

// MonClientFrom retrieves the mon-client RequireClientToken authenticated
// for this request. It returns nil rather than panicking when called on a
// route that never ran the middleware, so a wiring mistake shows up as an
// obvious nil-pointer bug at the call site instead of a security-relevant
// silent success.
func MonClientFrom(c *gin.Context) *store.MonClient {
	v, ok := c.Get(monClientContextKey)
	if !ok {
		return nil
	}
	mc, _ := v.(*store.MonClient)
	return mc
}
