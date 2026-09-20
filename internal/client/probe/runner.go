package probe

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// Fn is one target's probe, already bound to everything it needs but the
// cycle's context: the probe URL, the client token, the tunnel's material
// (an xray socks port or a parsed AWG config) and the budgets. The config
// applier builds one Fn per target when it applies a revision
// (internal/client/app), which is what keeps this package free of any
// import of internal/client/awg — awg already imports probe for Do,
// Classify and Budgets, so a Runner that knew how to build AWG probes
// itself would close an import cycle.
//
// A Fn never returns an error: a failed probe is a Result with ok=false
// and a reason (protocol §5.3), because a cycle must carry exactly one
// line per target no matter what happened to the tunnel.
type Fn func(ctx context.Context, key proto.TargetKey) proto.Result

// Runner runs one probe cycle: every target in parallel, each under its
// own budget (spec §5: "все targets параллельно, каждая проба под
// context.WithTimeout(budgetMs)"). It holds no state between cycles —
// what varies from cycle to cycle (which targets exist, what their probes
// are) arrives as arguments, so applying a new revision is just handing
// Cycle a different map next time.
type Runner struct {
	// Log receives the runner's own lines (a probe that panicked). The
	// per-probe result lines are written by the probes themselves
	// (Prober.Xray, awg.Prober.Probe, spec §7). Nil means slog.Default().
	Log *slog.Logger
}

// NewRunner returns a Runner logging to log (nil: slog.Default()).
func NewRunner(log *slog.Logger) *Runner { return &Runner{Log: log} }

// Cycle probes every target in probes and returns their results in a
// stable order (by inbound kind, inbound id, then path) regardless of
// which probe finished first — a heartbeat body that reshuffles itself
// every minute would make diffing two cycles in a log needlessly hard,
// and mon-server keys results by target anyway.
//
// Each probe runs under context.WithTimeout(ctx, b.Budget), so one hung
// tunnel costs the cycle one budget, not one budget per hung target: the
// whole cycle finishes in about b.Budget even when every target hangs.
// The deadline is on top of whatever ctx already carries — a cancelled ctx
// (shutdown) still ends every probe immediately.
//
// A probe that panics is turned into a failed result (http_error, with the
// panic text as detail) rather than taking the process down: one target
// whose material makes its prober panic must not stop a mon-client from
// reporting every other target. The panic is logged with its stack at
// error level, because it is always a bug in mon-client, never a tunnel
// being down.
func (r *Runner) Cycle(ctx context.Context, probes map[proto.TargetKey]Fn, b Budgets) []proto.Result {
	keys := make([]proto.TargetKey, 0, len(probes))
	for k := range probes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })

	// Non-nil even when empty: a cycle with no targets is a normal state
	// (spec §4.4, "цикл идёт пустым") and its results must encode as [],
	// not null.
	results := make([]proto.Result, len(keys))

	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Add(1)
		go func(i int, k proto.TargetKey) {
			defer wg.Done()
			results[i] = r.one(ctx, k, probes[k], b)
		}(i, k)
	}
	wg.Wait()
	return results
}

// one runs a single probe under its budget, converting a panic into a
// result so the cycle survives it.
func (r *Runner) one(ctx context.Context, k proto.TargetKey, fn Fn, b Budgets) (res proto.Result) {
	defer func() {
		if p := recover(); p != nil {
			r.log().Error("probe panicked", "target", k.String(), "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			reason := proto.ReasonHTTPError
			detail := trim(fmt.Sprintf("probe panicked: %v", p))
			res = proto.Result{TargetKey: k, Reason: &reason, Detail: &detail}
		}
	}()

	pctx, cancel := context.WithTimeout(ctx, b.Budget)
	defer cancel()
	return fn(pctx, k)
}

// less orders two target keys: kind, then inbound id, then path — the
// order Cycle's results always come back in.
func less(a, b proto.TargetKey) bool {
	if a.InboundKind != b.InboundKind {
		return a.InboundKind < b.InboundKind
	}
	if a.InboundID != b.InboundID {
		return a.InboundID < b.InboundID
	}
	return a.Path < b.Path
}

// log is the logger to use, defaulting to slog.Default() so a zero Runner
// is usable (Prober and xray.New share the convention).
func (r *Runner) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}
