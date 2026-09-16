// Package server is mon-server's single HTTPS listener (mon-server.md §2).
//
// One port carries all three groups: /v1/* is the mon-client protocol,
// /admin/* is the admin UI, and /healthz answers 200 to anyone with no auth
// and without touching the panel or the database. The groups are told apart by
// path, not by port, because mon-clients reach heartbeat, registration and
// config directly while a tunnel probe arrives through the target's tunnel.
//
// The package takes its route groups as http.Handler values instead of
// importing internal/api and internal/admin, so the listener can be started in
// tests with stub handlers and no dependencies.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Route prefixes and paths served by the listener (mon-server.md §10).
const (
	// V1Prefix is the mon-client protocol group.
	V1Prefix = "/v1/"
	// AdminPrefix is the admin UI group, pages and /admin/api/*.
	AdminPrefix = "/admin/"
	// HealthPath is the unauthenticated liveness probe.
	HealthPath = "/healthz"
)

// Timeouts for the listener. mon-server is exposed directly to the internet
// with no reverse proxy in front, so a header timeout is mandatory; the rest
// are generous for JSON requests of a few kilobytes.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20
)

// Options configures the listener.
type Options struct {
	// Addr is the listen address, ":443" in production. ":0" binds a free
	// port, which tests read back from Server.Addr.
	Addr string
	// TLSConfig comes from internal/tlsx. A nil config serves plain HTTP and
	// is meant for tests and e2e only.
	TLSConfig *tls.Config
	// V1 handles the mon-client protocol; mounted at /v1/ with the prefix
	// intact, so it registers full patterns such as "GET /v1/config". May be
	// nil while the group does not exist yet, in which case /v1/* is 404.
	V1 http.Handler
	// Admin handles the admin UI, mounted at /admin/ the same way. May be nil.
	Admin http.Handler
	// Log receives listener lifecycle events and net/http's own errors.
	// May be nil.
	Log *slog.Logger
	// Clock is the injected time source. May be nil.
	Clock clock.Clock
}

// Server is the bound listener and the mux in front of the route groups.
type Server struct {
	http  *http.Server
	ln    net.Listener
	addr  string
	log   *slog.Logger
	clock clock.Clock

	closeOnce sync.Once
}

// New builds the mux and binds the listen address. Binding here rather than in
// Serve means Addr reports the real port before anything is served, so a test
// on ":0" can address the server without racing the accept loop: connections
// made before Serve runs wait in the listen backlog.
func New(o Options) (*Server, error) {
	if o.Addr == "" {
		return nil, errors.New("server: listen address is required")
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	clk := o.Clock
	if clk == nil {
		clk = clock.System{}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, health)
	// The groups keep their prefix: they register full patterns themselves.
	if o.V1 != nil {
		mux.Handle(V1Prefix, o.V1)
	}
	if o.Admin != nil {
		mux.Handle(AdminPrefix, o.Admin)
	}

	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, fmt.Errorf("server: listen on %s: %w", o.Addr, err)
	}

	var tlsConfig *tls.Config
	if o.TLSConfig != nil {
		// Cloned because net/http appends h2 to the config it is given.
		tlsConfig = o.TLSConfig.Clone()
	}
	return &Server{
		http: &http.Server{
			Handler:           mux,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(log.With("src", "net/http").Handler(), slog.LevelWarn),
		},
		ln:    ln,
		addr:  ln.Addr().String(),
		log:   log,
		clock: clk,
	}, nil
}

// Addr is the bound address, with the real port when Options.Addr used ":0".
func (s *Server) Addr() string { return s.addr }

// Handler is the mux, exposed so tests and e2e harnesses can drive the routes
// without a socket.
func (s *Server) Handler() http.Handler { return s.http.Handler }

// Serve accepts connections and blocks until the server is shut down. It
// returns nil for an orderly stop and the listener error otherwise.
//
// Cancelling ctx starts the same graceful shutdown as calling Shutdown and
// Serve then returns once it is done: ctx is not handed to the request
// handlers, so in-flight requests are allowed to finish (mon-server.md §2).
func (s *Server) Serve(ctx context.Context) error {
	shutdownDone := make(chan struct{})
	stopWatch := context.AfterFunc(ctx, func() {
		defer close(shutdownDone)
		s.log.Info("shutdown requested, context cancelled")
		if err := s.Shutdown(context.WithoutCancel(ctx)); err != nil {
			s.log.Error("graceful shutdown failed", "err", err)
		}
	})

	started := s.clock.Now()
	s.log.Info("listening", "addr", s.addr, "tls", s.http.TLSConfig != nil)

	var err error
	if s.http.TLSConfig != nil {
		// ServeTLS, not tls.NewListener: it is what adds h2 and http/1.1 to
		// NextProtos next to the acme-tls/1 entry tlsx put there, and wires
		// up the HTTP/2 handler for the protocol it advertises.
		err = s.http.ServeTLS(s.ln, "", "")
	} else {
		err = s.http.Serve(s.ln)
	}
	if !stopWatch() {
		// The context was cancelled first: accepting stops right away, so
		// wait here until the handlers it is draining have finished.
		<-shutdownDone
	}
	if errors.Is(err, http.ErrServerClosed) {
		s.log.Info("stopped", "addr", s.addr, "uptime", s.clock.Now().Sub(started).String())
		return nil
	}
	return err
}

// Shutdown stops accepting connections and waits for the handlers that are
// still running, until they finish or ctx is done.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	// Shutdown closes the listeners it is serving on; this covers the case
	// where Serve was never called.
	s.closeOnce.Do(func() {
		if cerr := s.ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) && err == nil {
			err = fmt.Errorf("close listener: %w", cerr)
		}
	})
	if err != nil {
		return fmt.Errorf("server: shutdown: %w", err)
	}
	return nil
}

// health answers the unauthenticated liveness probe of mon-server.md §10. It
// depends on nothing: no panel, no database, no session.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}
