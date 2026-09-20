package probe

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// quietRunner is a Runner whose logs go nowhere, so a test that
// deliberately panics a probe does not spray a stack trace over the test
// output.
func quietRunner() *Runner {
	return NewRunner(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func key(kind string, id int, path string) proto.TargetKey {
	return proto.TargetKey{InboundKind: kind, InboundID: id, Path: path}
}

// TestRunner_CycleRunsProbesInParallel is spec §5's "все targets
// параллельно, каждая проба под context.WithTimeout(budgetMs)": five
// targets that all hang must cost the cycle one budget, not five.
func TestRunner_CycleRunsProbesInParallel(t *testing.T) {
	const budget = 300 * time.Millisecond

	hang := func(ctx context.Context, k proto.TargetKey) proto.Result {
		<-ctx.Done()
		reason := proto.ReasonProbeTimeout
		return proto.Result{TargetKey: k, Reason: &reason}
	}
	probes := map[proto.TargetKey]Fn{}
	for i := range 5 {
		probes[key("xray", i, "proxy")] = hang
	}

	start := time.Now()
	results := quietRunner().Cycle(context.Background(), probes, Budgets{Budget: budget})
	elapsed := time.Since(start)

	if len(results) != 5 {
		t.Fatalf("len(results) = %d, want 5", len(results))
	}
	if elapsed > 3*budget/2 {
		t.Fatalf("cycle took %s, want about one budget (%s) — probes did not run in parallel", elapsed, budget)
	}
	for _, r := range results {
		if r.Ok || r.Reason == nil || *r.Reason != proto.ReasonProbeTimeout {
			t.Fatalf("result %+v, want every hung probe to time out", r)
		}
	}
}

// TestRunner_CycleAppliesTheBudgetPerProbe checks each probe really gets
// its own deadline rather than sharing the caller's context.
func TestRunner_CycleAppliesTheBudgetPerProbe(t *testing.T) {
	const budget = 2 * time.Second

	var deadlines atomic.Int64
	fn := func(ctx context.Context, k proto.TargetKey) proto.Result {
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= budget+time.Second {
			deadlines.Add(1)
		}
		return proto.Result{TargetKey: k, Ok: true}
	}
	probes := map[proto.TargetKey]Fn{
		key("xray", 12, "proxy"):  fn,
		key("xray", 12, "direct"): fn,
	}

	quietRunner().Cycle(context.Background(), probes, Budgets{Budget: budget})

	if got := deadlines.Load(); got != 2 {
		t.Fatalf("%d of 2 probes saw a budget deadline", got)
	}
}

// TestRunner_CycleOrdersResults checks the stable order a heartbeat body
// relies on: kind, then inbound id, then path — whatever order the probes
// finished in.
func TestRunner_CycleOrdersResults(t *testing.T) {
	// The awg probe sleeps so that, unordered, it would land last.
	slow := func(ctx context.Context, k proto.TargetKey) proto.Result {
		time.Sleep(50 * time.Millisecond)
		return proto.Result{TargetKey: k, Ok: true}
	}
	fast := func(ctx context.Context, k proto.TargetKey) proto.Result {
		return proto.Result{TargetKey: k, Ok: true}
	}
	probes := map[proto.TargetKey]Fn{
		key("xray", 12, "proxy"):  fast,
		key("xray", 2, "direct"):  fast,
		key("awg", 0, "proxy"):    slow,
		key("xray", 12, "direct"): fast,
	}

	results := quietRunner().Cycle(context.Background(), probes, Budgets{Budget: time.Second})

	want := []proto.TargetKey{
		key("awg", 0, "proxy"),
		key("xray", 2, "direct"),
		key("xray", 12, "direct"),
		key("xray", 12, "proxy"),
	}
	if len(results) != len(want) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(want))
	}
	for i, w := range want {
		if results[i].TargetKey != w {
			t.Fatalf("results[%d].TargetKey = %v, want %v", i, results[i].TargetKey, w)
		}
	}
}

// TestRunner_CycleRecoversAPanickingProbe checks one broken probe cannot
// take the cycle (or the process) down: it becomes a failed result and
// every other target is still reported.
func TestRunner_CycleRecoversAPanickingProbe(t *testing.T) {
	probes := map[proto.TargetKey]Fn{
		key("xray", 1, "proxy"): func(ctx context.Context, k proto.TargetKey) proto.Result {
			panic("boom")
		},
		key("xray", 2, "proxy"): func(ctx context.Context, k proto.TargetKey) proto.Result {
			return proto.Result{TargetKey: k, Ok: true}
		},
	}

	results := quietRunner().Cycle(context.Background(), probes, Budgets{Budget: time.Second})

	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if results[0].Ok || results[0].Reason == nil || *results[0].Reason != proto.ReasonHTTPError {
		t.Fatalf("panicking probe = %+v, want a failed http_error result", results[0])
	}
	if results[0].Detail == nil || !strings.Contains(*results[0].Detail, "boom") {
		t.Fatalf("detail = %v, want the panic text", results[0].Detail)
	}
	if !results[1].Ok {
		t.Fatalf("second probe = %+v, want it unaffected", results[1])
	}
}

// TestRunner_CycleWithNoTargets checks spec §4.4's empty cycle: no probes
// is a normal state, and its results encode as [] rather than null.
func TestRunner_CycleWithNoTargets(t *testing.T) {
	results := quietRunner().Cycle(context.Background(), nil, Budgets{Budget: time.Second})
	if results == nil {
		t.Fatal("results = nil, want an empty non-nil slice")
	}
	if len(results) != 0 {
		t.Fatalf("len(results) = %d, want 0", len(results))
	}
}
