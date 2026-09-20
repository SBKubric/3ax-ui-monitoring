// Package app is mon-client's run loop: the thing that turns a registered
// box into a mon-client (spec §4–§6). It fetches the config document,
// hands it to an Applier, and then, once per interval, probes every target
// in parallel, buffers the cycle and delivers the buffer in one heartbeat.
//
// Everything it does not own itself arrives through Deps, so the loop can
// be driven a single iteration at a time (Loop.Once) against the protocol
// stub with a fake clock and an injected sleeper — a loop whose tests had
// to wait out a 60-second interval would never be run.
package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Spec §5's probe defaults, in the units the config document carries them
// (protocol §4.2). They are what a mon-client runs on before it has ever
// seen a document — a 503 config_not_ready on the first boot must still
// produce a running, heartbeating box (spec §4.4) rather than one waiting
// for numbers it may not get for hours. probe.BudgetsFrom applies the same
// defaults to the four probe budgets; these are the two the loop itself
// needs plus the jitter.
const (
	DefaultIntervalMs         = 60_000
	DefaultStartJitterMs      = 5_000
	DefaultHeartbeatTimeoutMs = 10_000
)

// maxConfigError is spec §4.3's bound on the configError text carried in
// every heartbeat ("первая строка ошибки, ≤ 256 символов").
const maxConfigError = 256

// Applier owns everything that happens between two cycles when a revision
// changes (spec §4.3): writing xray.json, testing it, restarting the xray
// child, recording appliedRevision in state.json — and, whatever the
// outcome, saying which probes the next cycle should run.
//
// Step 8 implements it for real; step 7 ships ProvisionalApplier, which
// builds the probes but touches neither xray.json nor the xray child.
// The contract, which step 8 must keep:
//
//   - Apply is called by the loop only between cycles, never while probes
//     are in flight, and may block for as long as a restart takes.
//   - Apply returning nil means the document was applied: the applier has
//     already updated state.File.AppliedRevision and saved it through
//     state.Dir, and Applied now reports the new document with a nil
//     error.
//   - Apply returning an error means the old revision stays in force (spec
//     §4.3): the applier keeps serving the previous document and probes
//     from Applied, and reports the error there as the configError every
//     heartbeat carries until the next successful apply.
//   - Applied is called once per cycle and must be cheap. Its doc may be
//     nil (nothing applied yet — the loop then probes nothing and still
//     heartbeats); its probes map is keyed by target and may be empty; its
//     error is the configError, not a reason to stop.
type Applier interface {
	Apply(ctx context.Context, doc *proto.ConfigDoc) error
	Applied() (doc *proto.ConfigDoc, probes map[proto.TargetKey]probe.Fn, err error)
}

// CycleGuard is an optional extension of Applier for an applier that has
// to know when probes are in flight. Spec §4 step 3 says a revision is
// applied "между циклами: дождаться проб в полёте" — with Once and Apply
// called from one goroutine that is already true, but an applier that
// restarts the xray child every probe dials through cannot rely on its
// caller's goroutine discipline for that. RevisionApplier implements it
// with a read/write lock: every cycle takes the read side, an apply the
// write side.
//
// Once calls the pair around the cycle when the Applier implements it;
// an applier that does not (the tests' fake) is simply not guarded.
type CycleGuard interface {
	BeginCycle()
	EndCycle()
}

// Deps are everything the loop needs and does not build itself. Every
// field that has a sensible production default gets one in NewLoop, so a
// test only overrides the seams it wants to control (Clock, Sleep, Rand).
type Deps struct {
	// API talks to mon-server off-tunnel: GET /v1/config and POST
	// /v1/heartbeat (spec §4, §6).
	API *api.Client
	// State is the state directory. The loop itself never writes it — the
	// Applier does, when it records a new appliedRevision — but it is here
	// because the Applier is handed it by the same wiring and step 9's
	// 401 branch (state.Clear) belongs to this loop.
	State *state.Dir
	// File is the loaded state.json. AppliedRevision is read from it every
	// cycle (it is what the heartbeat's configRevision reports and what a
	// response's revision is compared against) and written by the Applier.
	File *state.File
	// Buffer is cycles.json (spec §6).
	Buffer *heartbeat.Buffer
	// Runner runs one cycle's probes in parallel.
	Runner *probe.Runner
	// Applier converges the box on a config document (see Applier).
	Applier Applier
	// Clock stamps each cycle's ts and computes uptimeMs. Defaults to
	// clock.Real.
	Clock clock.Clock
	// Sleep is the interval wait; the zero value is a cancellable timer.
	// Tests inject one that advances the fake Clock instead, so a full
	// cycle costs no wall-clock time at all.
	Sleep func(ctx context.Context, d time.Duration) error
	// Rand draws the start jitter (spec §5). Defaults to a PCG seeded from
	// crypto/rand — the jitter exists to spread the cycle starts of many
	// boxes, so every box seeding it identically would defeat it.
	Rand *mrand.Rand
	// Log receives the loop's spec §7 lines ("ack 1441", "buffered 3
	// cycles"). Nil means slog.Default().
	Log *slog.Logger
	// Version and XrayVersion fill the heartbeat's client block (protocol
	// §5.3). XrayVersion is a function because the xray child may be
	// restarted under a new binary between heartbeats; nil reports "".
	Version     string
	XrayVersion func() string
	// StartedAt is the process start, for uptimeMs.
	StartedAt time.Time
}

// Loop is one running mon-client. It is not safe for concurrent use: Run
// (or repeated Once) owns it.
type Loop struct {
	d Deps

	// needConfig is "fetch GET /v1/config before the next cycle" — true at
	// start (spec §4.1) and set again whenever a heartbeat answers with a
	// revision other than the applied one (spec §6).
	needConfig bool
	// first marks the cycle that has not run yet, the only one the start
	// jitter applies to (spec §5).
	first bool
}

// NewLoop returns a Loop over d, filling in every dependency with a
// production default that d left nil.
func NewLoop(d Deps) *Loop {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Rand == nil {
		d.Rand = mrand.New(mrand.NewPCG(seed(), seed()))
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Runner == nil {
		d.Runner = probe.NewRunner(d.Log)
	}
	if d.StartedAt.IsZero() {
		d.StartedAt = d.Clock.Now()
	}
	return &Loop{d: d, needConfig: true, first: true}
}

// Run drives the loop until ctx ends (a normal shutdown, reported as nil)
// or mon-server refuses this mon-client outright.
//
// api.ErrTokenRevoked (401) and api.ErrDisabled (403) are returned
// unwrapped: spec §6 gives them two very different answers — clear the
// state file and register again, versus keep the state file and heartbeat
// every 5 minutes — and step 9 owns both. Every other failure (mon-server
// down, a 5xx, a timeout, a config that would not apply) is handled inside
// the loop and never stops the probes (spec §6: "Пробы при этом
// продолжаются").
func (l *Loop) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := l.d.Sleep(ctx, l.nextWait()); err != nil {
			return nil // ctx ended during the wait: an ordinary shutdown
		}
		if err := l.Once(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			l.log().Error("mon-client stopping", "error", err)
			return err
		}
	}
}

// Once runs exactly one iteration — fetch the config if it is due, probe
// every target, buffer the cycle, deliver the buffer, act on the answer —
// without any waiting of its own. Run calls it once per interval; a test
// calls it directly, which is why the interval wait lives in Run.
func (l *Loop) Once(ctx context.Context) error {
	l.first = false

	if l.needConfig {
		if err := l.fetchAndApply(ctx); err != nil {
			return err
		}
	}

	doc, results, ts, configErr := l.cycle(ctx)
	l.d.Buffer.Add(ts, results)

	hb := &proto.HeartbeatRequest{
		MonClientID:    l.d.File.MonClientID,
		ConfigRevision: l.d.File.AppliedRevision,
		Client: proto.ClientInfo{
			Version:     l.d.Version,
			XrayVersion: l.xrayVersion(),
			UptimeMs:    l.uptimeMs(),
			ConfigError: configErrorText(configErr),
		},
		Cycles: l.d.Buffer.Pending(),
	}

	hctx, cancel := context.WithTimeout(ctx, l.heartbeatTimeout(doc))
	defer cancel()
	resp, err := heartbeat.Send(hctx, l.d.API, hb)
	if err != nil {
		// Spec §6: an unacknowledged cycle stays in the buffer, flagged,
		// and rides along with the next heartbeat. This is also where a
		// 401/403 lands, and those two must reach the caller — but the
		// cycle is marked either way, since it was not delivered.
		if markErr := l.d.Buffer.MarkUnverified(); markErr != nil {
			l.log().Error("cycles buffer not persisted", "error", markErr)
		}
		if errors.Is(err, api.ErrTokenRevoked) || errors.Is(err, api.ErrDisabled) {
			return err
		}
		l.log().Info(fmt.Sprintf("buffered %d cycles", len(l.d.Buffer.Pending())), "error", err)
		return nil
	}

	if err := l.d.Buffer.Ack(resp.AckSeq); err != nil {
		l.log().Error("cycles buffer not persisted", "error", err)
	}
	// Spec §7's heartbeat line.
	l.log().Info(fmt.Sprintf("ack %d", resp.AckSeq))

	if resp.ConfigRevision != l.d.File.AppliedRevision {
		// Spec §6: a revision change is acted on *after* the current
		// cycle, so the next iteration fetches and applies it before it
		// probes.
		l.log().Info(fmt.Sprintf("config revision changed to %s", resp.ConfigRevision))
		l.needConfig = true
	}
	return nil
}

// cycle runs one probe cycle against whatever is applied and returns it
// together with the applied document, the configError and the cycle's
// start timestamp.
//
// It is a method of its own because of the guard around it: while the
// cycle runs, an Applier that is a CycleGuard cannot swap the probe set
// under it (spec §4 step 3). The results are then filtered against that
// same probe set: spec §4 step 3 gives removed targets no grace ("грейса
// нет: результаты по удалённым targets отбрасываются"), and while the
// runner only ever probes what it was handed, a result for a key the
// applied document no longer has must not reach a heartbeat even if some
// future applier hands one back.
func (l *Loop) cycle(ctx context.Context) (doc *proto.ConfigDoc, results []proto.Result, ts int64, configErr error) {
	if g, ok := l.d.Applier.(CycleGuard); ok {
		g.BeginCycle()
		defer g.EndCycle()
	}
	doc, probes, configErr := l.d.Applier.Applied()
	ts = clock.Ms(l.d.Clock.Now())
	results = l.d.Runner.Cycle(ctx, probes, probe.BudgetsFrom(probeParams(doc)))
	return doc, applied(results, probes), ts, configErr
}

// applied drops every result whose target is not in the applied probe set
// (spec §4 step 3). The slice stays non-nil when empty: a cycle with no
// results encodes as [], not null (protocol §5.3).
func applied(results []proto.Result, probes map[proto.TargetKey]probe.Fn) []proto.Result {
	kept := make([]proto.Result, 0, len(results))
	for _, r := range results {
		if _, ok := probes[r.TargetKey]; ok {
			kept = append(kept, r)
		}
	}
	return kept
}

// fetchAndApply performs spec §4.1's GET /v1/config and hands the document
// to the Applier.
//
// A 503 config_not_ready on a box that has applied nothing yet is not a
// failure to retry silently: spec §4.4 says such a box runs empty cycles
// and heartbeats anyway, so an empty document with the spec §5 defaults is
// applied and the fetch stays due for the next iteration. Any other
// failure leaves whatever is applied in force and retries next iteration
// too — 401/403 excepted, which belong to the caller.
func (l *Loop) fetchAndApply(ctx context.Context) error {
	doc, err := l.d.API.Config(ctx)
	if err != nil {
		if errors.Is(err, api.ErrTokenRevoked) || errors.Is(err, api.ErrDisabled) {
			return err
		}
		l.log().Warn("config not fetched", "error", err)
		if applied, _, _ := l.d.Applier.Applied(); applied == nil {
			doc = l.emptyDoc()
			if applyErr := l.d.Applier.Apply(ctx, doc); applyErr != nil {
				l.log().Warn("config not applied", "error", applyErr)
			}
		}
		return nil
	}

	l.needConfig = false
	if err := l.d.Applier.Apply(ctx, doc); err != nil {
		// Spec §4.3: the old revision stays in force and the error is
		// reported as configError on every heartbeat until a later
		// revision applies cleanly; the applier keeps it for us.
		l.log().Warn("config not applied", "error", err)
		return nil
	}
	// The spec §7 line for a successful apply is written by the Applier,
	// which is the only thing that knows what the revision turned into
	// (how many xray- and AWG-targets, and whether the child restarted).
	return nil
}

// emptyDoc is the document a mon-client runs on when mon-server has none
// for it yet (spec §4.4): no targets, spec §5's default timings.
func (l *Loop) emptyDoc() *proto.ConfigDoc {
	return &proto.ConfigDoc{
		MonClientID: l.d.File.MonClientID,
		Probe: proto.ProbeParams{
			IntervalMs:         DefaultIntervalMs,
			BudgetMs:           int64(probe.DefaultBudget / time.Millisecond),
			ConnectMs:          int64(probe.DefaultConnect / time.Millisecond),
			TlsMs:              int64(probe.DefaultTLS / time.Millisecond),
			HeadersMs:          int64(probe.DefaultHeaders / time.Millisecond),
			StartJitterMs:      DefaultStartJitterMs,
			HeartbeatTimeoutMs: DefaultHeartbeatTimeoutMs,
		},
	}
}

// nextWait is how long Run waits before the next cycle: the applied
// document's intervalMs, except before the very first cycle, which waits
// only the start jitter.
//
// Spec §5 asks for "старт со случайным джиттером [0, startJitterMs]" — the
// jitter exists so that a fleet of boxes restarted together does not hit
// mon-server in lockstep. Waiting a whole interval *plus* jitter before
// the first cycle would instead leave a freshly started box silent for a
// minute, which is exactly the minute an operator watching a new
// registration is looking at.
func (l *Loop) nextWait() time.Duration {
	doc, _, _ := l.d.Applier.Applied()
	p := probeParams(doc)
	if l.first {
		jitter := p.StartJitterMs
		if jitter <= 0 {
			return 0
		}
		return time.Duration(l.d.Rand.Int64N(jitter)) * time.Millisecond
	}
	interval := p.IntervalMs
	if interval <= 0 {
		interval = DefaultIntervalMs
	}
	return time.Duration(interval) * time.Millisecond
}

// heartbeatTimeout is the deadline one heartbeat runs under (spec §6's
// heartbeatTimeoutMs), defaulted like everything else in probeParams.
func (l *Loop) heartbeatTimeout(doc *proto.ConfigDoc) time.Duration {
	ms := probeParams(doc).HeartbeatTimeoutMs
	if ms <= 0 {
		ms = DefaultHeartbeatTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// uptimeMs is the process' age (protocol §5.3's client.uptimeMs), never
// negative even if the clock moved backwards between two reads.
func (l *Loop) uptimeMs() int64 {
	d := l.d.Clock.Now().Sub(l.d.StartedAt)
	if d < 0 {
		return 0
	}
	return int64(d / time.Millisecond)
}

// xrayVersion reports the xray child's version for the heartbeat, or ""
// when there is no child to ask (an AWG-only box, or one whose xray never
// started).
func (l *Loop) xrayVersion() string {
	if l.d.XrayVersion == nil {
		return ""
	}
	return l.d.XrayVersion()
}

func (l *Loop) log() *slog.Logger { return l.d.Log }

// probeParams is doc.Probe with a nil doc treated as "no document yet" —
// the zero ProbeParams, which every caller then defaults field by field
// (probe.BudgetsFrom does the same for the four probe budgets).
func probeParams(doc *proto.ConfigDoc) proto.ProbeParams {
	if doc == nil {
		return proto.ProbeParams{IntervalMs: DefaultIntervalMs, StartJitterMs: DefaultStartJitterMs, HeartbeatTimeoutMs: DefaultHeartbeatTimeoutMs}
	}
	return doc.Probe
}

// configErrorText renders an Applier's error as protocol §5.3's
// client.configError: its first line, at most 256 characters (spec §4.3).
// A nil error is a nil pointer, which is the null the protocol's example
// shows for a healthy mon-client — distinct from an empty string.
func configErrorText(err error) *string {
	if err == nil {
		return nil
	}
	text := firstLine(err.Error())
	return &text
}

// defaultSleep is Deps.Sleep's production behaviour: an ordinary
// cancellable timer (the same shape register.Run uses).
func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// seed draws one PCG seed word from crypto/rand, falling back to the
// clock-free zero value only if the host's randomness is broken — in which
// case the jitter is degenerate but the loop still runs.
func seed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b[:])
}
