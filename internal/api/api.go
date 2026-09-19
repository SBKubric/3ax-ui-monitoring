// Package api is the gin skeleton every mon-server HTTP handler hangs off
// (architecture brief §2: "gin engine, /healthz, /v1 group, error helper").
// This step only builds the engine, the two route groups and /healthz;
// steps 4, 5, 6, 8 and 10 register their own handlers and middleware
// (client-token auth, admin sessions) onto the groups this package exposes.
package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Server is mon-server's single gin engine plus the two route groups later
// steps attach handlers to. There is exactly one Server per process because
// there is exactly one HTTPS listener (spec §2): /v1/* for the mon-client
// protocol and /admin/* for the admin UI share it, distinguished by path,
// not by port.
type Server struct {
	// Engine is the http.Handler internal/app hands to http.Server.
	Engine *gin.Engine
	// V1 is the mon-client protocol group (docs/spec/mon-protocol.md).
	// Step 4 adds registry.RequireClientToken and the registration/config/
	// heartbeat/probe handlers here.
	V1 *gin.RouterGroup
	// Admin is the admin UI group (spec §9). Step 10 adds the session
	// middleware and every /admin/* page and /admin/api/* handler here.
	Admin *gin.RouterGroup
}

// errorBody is the mon-client protocol's error envelope (protocol §1): a
// stable, machine-readable snake_case code a mon-client can branch on, plus
// a free-form message meant for mon-server's own logs and human debugging,
// not for the mon-client to parse.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Fail writes the protocol's error body with the given status and aborts
// the gin context, so a handler can call Fail and immediately return without
// separately remembering to call c.Abort() — forgetting that is how a
// handler accidentally falls through to a success response after already
// reporting an error.
func Fail(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, errorBody{Error: code, Message: msg})
}

// New builds mon-server's one gin.Engine (spec §2, §10): release mode
// (gin's debug mode logs request bodies and stack traces to stdout, which
// has no place in a production service), panic recovery so a handler bug
// becomes a 500 instead of taking the whole process down, a slog-based
// request logger, an unauthenticated /healthz, and the V1/Admin groups every
// later step builds on. internal/app calls this once at startup.
func New() *Server {
	gin.SetMode(gin.ReleaseMode)
	e := gin.New()
	// requestLogger is registered before gin.Recovery(), which makes
	// Recovery the *inner* middleware: gin runs middleware in registration
	// order, each one wrapping the next via c.Next(), so a panicking
	// handler unwinds into Recovery first, which recovers it and writes
	// the 500 response, and only then unwinds back out through
	// requestLogger's own post-c.Next() code, which logs that 500 with a
	// structured line. The reverse order would let the panic recover
	// inside Recovery without requestLogger ever getting to run its
	// logging code, so a panicking handler would leave no log line at all.
	e.Use(requestLogger(), gin.Recovery())

	// mon-server terminates TLS itself on a public IP with no reverse
	// proxy in front of it (spec §2, §2.1): there is nothing between a
	// client and this process that could legitimately set
	// X-Forwarded-For, so it must never be honoured. Trusting it would let
	// any client spoof c.ClientIP() and bypass the per-IP registration
	// rate limit (step 4, spec §6).
	if err := e.SetTrustedProxies(nil); err != nil {
		// SetTrustedProxies(nil) cannot fail in gin v1.12.0 (it only
		// validates a non-nil list of CIDRs/IPs); panicking here would
		// only ever fire on a gin upgrade that changes that contract, and
		// this is a one-time startup call, not a request path.
		panic(fmt.Sprintf("api: SetTrustedProxies(nil): %v", err))
	}

	// /healthz: no auth, only 200 (spec §2, §10) — a liveness probe must
	// never depend on the database, the panel, or anything else that could
	// be down for reasons that don't mean "restart me". HEAD is registered
	// alongside GET because some uptime monitors and load balancers probe
	// liveness with HEAD to avoid pulling a response body they discard
	// anyway.
	e.Match([]string{http.MethodGet, http.MethodHead}, "/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	v1 := e.Group("/v1")
	admin := e.Group("/admin")

	// Only /v1/* gets the protocol's JSON error envelope on a miss, so a
	// mon-client always has a body it can parse; /admin/* (and anything
	// else) keeps gin's default plain 404, since step 10 wants its own
	// admin-UI-flavoured not-found page rather than this one. The bare
	// path "/v1" (no trailing slash) counts as /v1/* too, so a request
	// that omits the slash still gets the protocol envelope instead of
	// falling through to the plain-404 branch.
	e.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == "/v1" || strings.HasPrefix(path, "/v1/") {
			Fail(c, http.StatusNotFound, "not_found", "no such route: "+path)
			return
		}
		c.Status(http.StatusNotFound)
	})

	return &Server{Engine: e, V1: v1, Admin: admin}
}

// requestLogger emits one slog line per request with the fields an operator
// actually wants (method, path, status, duration), skipping /healthz: an
// uptime monitor typically polls it every few seconds, and logging every
// poll would drown out everything else in the log.
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/healthz" {
			c.Next()
			return
		}
		start := time.Now()
		c.Next()
		slog.Info("http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}
}
