package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/register"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// disabledHeartbeatInterval is spec §6's "403 disabled → остановить пробы,
// heartbeat раз в 5 мин до 200": how long a disabled mon-client waits
// between the bare heartbeats that are the only thing it still sends.
const disabledHeartbeatInterval = 5 * time.Minute

// stopTimeout bounds the shutdown of one loop's probing machinery (the
// xray child) when the loop ends on a 401 or a 403. A child that has not
// gone in five seconds is stuck, and the supervisor must still get on with
// re-registering or with waiting out the disable.
const stopTimeout = 5 * time.Second

// LoopFactory builds one running identity's Loop: the cycles buffer, the
// config applier, the probe runner and the Loop over them, together with
// the function that stops whatever the loop started (the xray child).
//
// It is a seam because the supervisor owns *when* a loop exists — a 401
// throws the identity away and a 403 suspends it — while cmd/mon-client
// owns *what* a loop is made of (an xray binary path, a state directory, a
// logger). The stop function is called exactly once per built loop, after
// Run returns, before anything else happens to that identity.
type LoopFactory func(file *state.File, client *api.Client) (loop *Loop, stop func(ctx context.Context) error, err error)

// ClientInfoSource is the one thing the supervisor asks a built loop for
// while that loop is not running: protocol §5.3's client block, so the
// bare heartbeats of disabled mode carry the same xrayVersion and
// configError an ordinary heartbeat would. *Loop satisfies it.
//
// It is an interface rather than a direct call on *Loop because it is the
// whole of what the supervisor needs from a stopped loop, and stating that
// keeps the disabled branch from growing a second use of a loop it has
// deliberately taken out of service.
type ClientInfoSource interface {
	ClientInfo() proto.ClientInfo
}

// SupervisorDeps are everything RunSupervisor needs. Clock, Sleep and Rand
// exist so a test can run a revocation and a five-minute disable in
// microseconds; everything else is what registration and the loop need
// anyway.
type SupervisorDeps struct {
	// ServerURL is spec §2's one mandatory parameter, the base URL of
	// every /v1 call.
	ServerURL string
	// HTTP is the client every api.Client is built over (no proxy: spec
	// §6's heartbeat goes past the tunnels). Nil means a plain
	// http.Client.
	HTTP *http.Client
	// Dir is the state directory. The supervisor is the only thing that
	// clears it (spec §6's 401 branch) and the only thing that loads it.
	Dir *state.Dir
	// Clock stamps the bare heartbeats' uptimeMs and backs registration's
	// expiry check. Defaults to clock.Real.
	Clock clock.Clock
	// Sleep is the five-minute wait between disabled heartbeats and
	// registration's backoff; the zero value is a cancellable timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Rand feeds the pairing code (spec §3). Nil means crypto/rand.
	Rand io.Reader
	// Log receives the supervisor's spec §7 lines ("token revoked,
	// re-registering", "enabled again, resuming"). Nil means
	// slog.Default().
	Log *slog.Logger
	// Version and Hostname go into every registration request and every
	// heartbeat's client block (protocol §2.1, §5.3).
	Version  string
	Hostname string
	// PublicIP is registration's best-effort publicIp (protocol §2.1).
	PublicIP func(ctx context.Context) string
	// NewLoop builds the loop for one identity (see LoopFactory).
	NewLoop LoopFactory
}

// RunSupervisor runs a mon-client for the life of ctx: it is the whole of
// spec §6's authentication story, sitting above the probe loop, which
// knows only how to probe and heartbeat.
//
// The shape is a single state machine over one box's identity:
//
//   - no state.json (or an unreadable one) → spec §3's registration, then
//     a loop over the token it yields;
//   - Loop.Run returning api.ErrTokenRevoked (401 on the heartbeat or on
//     GET /v1/config) → stop probing, clear state.json, register again
//     with a fresh pairing code (spec §6, protocol §2.3). The old token is
//     gone: nothing about the old identity is reused;
//   - Loop.Run returning api.ErrDisabled (403) → stop probing and send a
//     bare heartbeat every five minutes until one is answered 200, then
//     rebuild the loop over the same identity (spec §6). A 401 arriving
//     during that wait takes the branch above;
//   - anything else → the loop already handled it and kept probing (spec
//     §6: "Пробы при этом продолжаются"), so reaching RunSupervisor at all
//     means the run is over.
//
// A cancelled ctx is a normal shutdown and reported as nil, whatever the
// loop was doing at the time.
//
// # Why a 401 on a probe is not acted on here
//
// Spec §6 says "401 token_revoked на любой ручке", and GET /v1/probe is a
// ручка: a revoked token fails it too. probe.Do sees that 401 as an
// ordinary non-200 and classifies it as http_error (spec §5's dictionary
// has no token entry, and neither does the contract's), which is by
// design. The heartbeat that closes the very same cycle carries the
// authoritative answer — it is the one call that always happens, on every
// cycle, past every tunnel — so acting on a probe's 401 would only make
// the same decision a few hundred milliseconds earlier, at the cost of a
// mon-client that throws its identity away because one tunnel's egress
// mangled a response. The cycle's results are still delivered (flagged
// unverified) before the token is cleared, so mon-server loses nothing.
func RunSupervisor(ctx context.Context, d SupervisorDeps) error {
	s := &supervisor{d: d.withDefaults()}
	s.startedAt = s.d.Clock.Now()

	for {
		if ctx.Err() != nil {
			return nil
		}
		file, err := s.identity(ctx)
		if err != nil {
			return s.done(ctx, err)
		}
		client := api.New(s.d.ServerURL, s.d.HTTP)
		client.Token = file.Token

		reregister, err := s.serve(ctx, file, client)
		if err != nil {
			return s.done(ctx, err)
		}
		if !reregister {
			return nil
		}
	}
}

// supervisor is RunSupervisor's state: its dependencies and the process
// start the bare heartbeats report as uptimeMs.
type supervisor struct {
	d         SupervisorDeps
	startedAt time.Time
}

// withDefaults fills in every dependency a caller left nil, so the rest of
// this file never nil-checks.
func (d SupervisorDeps) withDefaults() SupervisorDeps {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.HTTP == nil {
		d.HTTP = &http.Client{}
	}
	return d
}

// done maps an error onto RunSupervisor's contract: a cancelled ctx is a
// normal shutdown (nil), everything else is the error the caller exits on.
func (s *supervisor) done(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// identity is "which mon-client is this box": the state file if there is a
// usable one, a completed registration otherwise.
//
// A state.json that exists but will not decode is treated exactly like one
// that is absent (spec §2: "Пропал или 401 — стереть и регистрироваться
// заново"): the operator is told why, the file is cleared, and the box
// registers. There is nothing else to be done with it — the token inside
// is unrecoverable either way.
func (s *supervisor) identity(ctx context.Context) (*state.File, error) {
	f, err := s.d.Dir.Load()
	switch {
	case err == nil:
		s.d.Log.Info(fmt.Sprintf("state loaded (mon-client %s)", f.MonClientID))
	default:
		if !errors.Is(err, state.ErrNoState) {
			s.d.Log.Warn("state file unreadable, clearing it", "error", err)
			if clearErr := s.d.Dir.Clear(); clearErr != nil {
				return nil, clearErr
			}
		}
		s.d.Log.Info("no state, registration required")
		if f, err = s.registerAgain(ctx); err != nil {
			return nil, err
		}
	}
	s.d.Log.Info(fmt.Sprintf("registered as %s", f.MonClientID))
	return f, nil
}

// registerAgain runs spec §3's registration to completion — a fresh
// pairing code, the 410/429/rejected handling and the backoff all live in
// register.Run, so the 401 branch gets exactly the same flow as a
// first boot rather than a shortcut of its own.
func (s *supervisor) registerAgain(ctx context.Context) (*state.File, error) {
	f, err := register.Run(ctx, register.Deps{
		API:      api.New(s.d.ServerURL, s.d.HTTP),
		State:    s.d.Dir,
		Clock:    s.d.Clock,
		Sleep:    s.d.Sleep,
		Log:      s.d.Log,
		Hostname: s.d.Hostname,
		Version:  s.d.Version,
		PublicIP: s.d.PublicIP,
		Rand:     s.d.Rand,
	})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return f, nil
}

// serve runs one identity for as long as it lasts, and reports whether the
// box has to register again.
//
// The inner loop is the disabled branch: a re-enabled mon-client keeps its
// identity, so it gets a freshly built loop rather than a fresh
// registration. The rebuild matters — the loop fetches GET /v1/config on
// start (spec §4.1), which is exactly right after a disable of unknown
// length, during which the config may have changed many times over.
func (s *supervisor) serve(ctx context.Context, file *state.File, client *api.Client) (reregister bool, err error) {
	for {
		loop, stop, err := s.d.NewLoop(file, client)
		if err != nil {
			return false, err
		}

		runErr := loop.Run(ctx)

		// Whatever ended the run, probing stops here: spec §6 says so
		// explicitly for both 401 and 403 ("остановить пробы"), and an
		// xray child left behind would hold the socks ports the next loop
		// wants.
		s.stop(stop)

		if ctx.Err() != nil {
			return false, nil
		}

		switch {
		case errors.Is(runErr, api.ErrTokenRevoked):
			return true, s.clearState()
		case errors.Is(runErr, api.ErrDisabled):
			revoked, err := s.waitEnabled(ctx, file, client, loop)
			if err != nil {
				return false, err
			}
			if ctx.Err() != nil {
				return false, nil
			}
			if revoked {
				return true, s.clearState()
			}
			// Spec §6: back to §4 — a new loop, the same token.
			s.d.Log.Info("enabled again, resuming")
		case runErr != nil:
			return false, runErr
		default:
			// Run only returns nil when ctx ended, which the check above
			// already caught; treat anything else the same way.
			return false, nil
		}
	}
}

// cyclesFileName is the buffer's file in the state directory (spec §2),
// named here because the 401 branch has to throw it away and the buffer
// package's own path comes from the same state.Dir.
const cyclesFileName = "cycles.json"

// clearState is spec §6's 401 answer: the token is gone, so the file that
// holds it goes too, and the box says so before it starts over.
//
// cycles.json goes with it. Those cycles were probed by the *old*
// identity, and the next heartbeat will be sent under a new monClientId
// with a seq counter mon-server has never seen: delivering them would
// attribute one mon-client's measurements to another and replay seqs from
// a counter that has just restarted at 1 (protocol §5.3's ackSeq is
// per-mon-client). Losing them is the right trade — a revoked mon-client's
// statistics are not worth mixing into its successor's.
func (s *supervisor) clearState() error {
	s.d.Log.Info("token revoked, re-registering")
	if err := s.d.Dir.Clear(); err != nil {
		return fmt.Errorf("clear state: %w", err)
	}
	if err := os.Remove(s.d.Dir.Path(cyclesFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear cycles: %w", err)
	}
	return nil
}

// stop runs a built loop's stop function under its own short deadline —
// its own, because the run's ctx is usually already cancelled by the time
// a mon-client is shutting down, and a child that is never SIGTERMed
// because the context was dead is a child left running.
func (s *supervisor) stop(stop func(ctx context.Context) error) {
	if stop == nil {
		return
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()
	if err := stop(stopCtx); err != nil {
		s.d.Log.Warn("probing not stopped cleanly", "error", err)
	}
}

// waitEnabled is spec §6's disabled mode: no probes at all, one bare
// heartbeat every five minutes, until mon-server answers 200 (the operator
// re-enabled this mon-client in the admin UI) or 401 (they revoked it
// instead, which is reported as revoked=true).
//
// The heartbeats are bare — the client block and no cycles — because there
// are no cycles: probing is stopped, and sending the cycles buffered
// before the disable would only re-deliver, five minutes at a time, data
// mon-server already refused to take. Those stay in cycles.json and ride
// along with the first real heartbeat after resuming (spec §6's buffer
// rules), which is the next loop's job.
func (s *supervisor) waitEnabled(ctx context.Context, file *state.File, client *api.Client, info ClientInfoSource) (revoked bool, err error) {
	s.d.Log.Info(fmt.Sprintf("mon-client disabled, probing stopped, heartbeat every %s", disabledHeartbeatInterval))
	for {
		if err := s.d.Sleep(ctx, disabledHeartbeatInterval); err != nil {
			return false, nil // ctx ended during the wait: an ordinary shutdown
		}

		hb := &proto.HeartbeatRequest{
			MonClientID:    file.MonClientID,
			ConfigRevision: file.AppliedRevision,
			Client:         s.clientInfo(info),
			// Non-nil so the body carries "cycles": [] rather than null
			// (protocol §5.3).
			Cycles: []proto.Cycle{},
		}

		hctx, cancel := context.WithTimeout(ctx, DefaultHeartbeatTimeoutMs*time.Millisecond)
		_, sendErr := heartbeat.Send(hctx, client, hb)
		cancel()

		switch {
		case sendErr == nil:
			return false, nil
		case errors.Is(sendErr, api.ErrTokenRevoked):
			// Revoked while disabled: the 401 branch wins (protocol §2.3).
			return true, nil
		case errors.Is(sendErr, api.ErrDisabled):
			// Still disabled — the expected answer, not worth a line every
			// five minutes at info level.
			s.d.Log.Debug("still disabled")
		default:
			if ctx.Err() != nil {
				return false, nil
			}
			// mon-server unreachable or failing: keep the same cadence
			// rather than escalating, since a disabled mon-client has
			// nothing to deliver anyway.
			s.d.Log.Warn("heartbeat while disabled failed", "error", sendErr)
		}
	}
}

// clientInfo is the bare heartbeats' client block (protocol §5.3).
//
// It is the stopped loop's own block — the version of xray it started,
// and the configError of whatever revision it last tried to apply, both of
// which a disabled mon-client still has to report (the operator looking at
// the admin UI is often disabling a box *because* its config is broken).
// Only uptimeMs is the supervisor's: the loop's clock starts when the loop
// is built, and a box that has been disabled and re-enabled a few times
// would otherwise report an uptime much shorter than the process'.
func (s *supervisor) clientInfo(info ClientInfoSource) proto.ClientInfo {
	c := proto.ClientInfo{}
	if info != nil {
		c = info.ClientInfo()
	}
	c.Version = s.d.Version
	c.UptimeMs = s.uptimeMs()
	return c
}

// uptimeMs is the process' age for the bare heartbeats' client block
// (protocol §5.3), computed the same way Loop does.
func (s *supervisor) uptimeMs() int64 {
	d := s.d.Clock.Now().Sub(s.startedAt)
	if d < 0 {
		return 0
	}
	return int64(d / time.Millisecond)
}
