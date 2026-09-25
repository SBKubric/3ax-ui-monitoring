package awg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func snap(t *testing.T, label string) (uint64, int) {
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	g := runtime.NumGoroutine()
	t.Logf("%-22s HeapInuse=%8d KB HeapObjects=%8d Sys=%8d KB goroutines=%d", label, m.HeapInuse/1024, m.HeapObjects, m.Sys/1024, g)
	return m.HeapInuse, g
}

func leakN() int {
	if v, err := strconv.Atoi(os.Getenv("LEAK_N")); err == nil {
		return v
	}
	return 40
}

func TestLeakProbeSuccess(t *testing.T) {
	far := startFarEnd(t, http.HandlerFunc(probeEcho))
	clientCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", far.port))
	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	key := proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "direct"}
	b := tunnelBudgets()
	run := func() {
		res := p.Probe(context.Background(), far.probeURL(), "tok", key, clientCfg, b)
		if !res.Ok {
			t.Fatalf("probe failed: %s %s", deref(res.Reason), deref(res.Detail))
		}
	}
	for i := 0; i < 5; i++ {
		run()
	}
	h0, g0 := snap(t, "success warm")
	n := leakN()
	for i := 1; i <= n; i++ {
		run()
		if i%(n/4) == 0 {
			snap(t, fmt.Sprintf("success after %d", i))
		}
	}
	h1, g1 := snap(t, "success end")
	t.Logf("SUCCESS per-probe: %d bytes heap, %.2f goroutines", (int64(h1)-int64(h0))/int64(n), float64(g1-g0)/float64(n))
	if os.Getenv("LEAK_PROF") != "" {
		f, _ := os.Create("/src/heap_success.pprof")
		pprof.WriteHeapProfile(f)
		f.Close()
		gf, _ := os.Create("/src/goroutines_success.txt")
		pprof.Lookup("goroutine").WriteTo(gf, 1)
		gf.Close()
	}
}

func TestLeakProbeNoHandshake(t *testing.T) {
	cfg := confFor(t, "203.0.113.7:51820", "")
	b := probe.Budgets{Budget: 5 * time.Second, Connect: 300 * time.Millisecond, TLS: time.Second, Headers: time.Second}
	key := proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}
	run := func() {
		res := Prober{Log: silent()}.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok", key, cfg, b)
		if res.Ok {
			t.Fatal("unexpected ok")
		}
	}
	for i := 0; i < 3; i++ {
		run()
	}
	h0, g0 := snap(t, "nohs warm")
	n := leakN()
	for i := 1; i <= n; i++ {
		run()
	}
	h1, g1 := snap(t, "nohs end")
	t.Logf("NOHANDSHAKE per-probe: %d bytes heap, %.2f goroutines", (int64(h1)-int64(h0))/int64(n), float64(g1-g0)/float64(n))
	if os.Getenv("LEAK_PROF") != "" {
		f, _ := os.Create("/src/heap_nohs.pprof")
		pprof.WriteHeapProfile(f)
		f.Close()
		gf, _ := os.Create("/src/goroutines_nohs.txt")
		pprof.Lookup("goroutine").WriteTo(gf, 1)
		gf.Close()
	}
}
