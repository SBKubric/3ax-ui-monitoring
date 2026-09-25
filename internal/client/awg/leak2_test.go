package awg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func procStatus() string {
	raw, _ := os.ReadFile("/proc/self/status")
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "VmRSS") || strings.HasPrefix(l, "VmHWM") {
			out = append(out, strings.Join(strings.Fields(l), " "))
		}
	}
	return strings.Join(out, " ")
}

func stats(t *testing.T, label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("%-10s %s | HeapInuse=%dMB HeapRetained(Sys-Released)=%dMB NumGC=%d goroutines=%d",
		label, procStatus(), m.HeapInuse>>20, (m.HeapSys-m.HeapReleased)>>20, m.NumGC, runtime.NumGoroutine())
}

// TestStandLike: one cycle = one successful AWG probe + one no-handshake AWG probe
// in parallel, then an idle gap, like the stand's 60 s cycle (compressed).
func TestStandLike(t *testing.T) {
	far := startFarEnd(t, http.HandlerFunc(probeEcho))
	okCfg := far.clientConf(t, fmt.Sprintf("127.0.0.1:%d", far.port))
	deadCfg := confFor(t, "203.0.113.7:51820", "")
	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: far.pool}}
	deadB := probe.Budgets{Budget: 5 * time.Second, Connect: time.Second, TLS: time.Second, Headers: time.Second}
	freeOS := os.Getenv("FREEOS") != ""
	stats(t, "start")
	cycles := leakN()
	for c := 1; c <= cycles; c++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.Probe(context.Background(), far.probeURL(), "tok", proto.TargetKey{InboundKind: "awg", Path: "direct"}, okCfg, tunnelBudgets()) }()
		go func() { defer wg.Done(); Prober{Log: silent()}.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok", proto.TargetKey{InboundKind: "awg", Path: "proxy"}, deadCfg, deadB) }()
		wg.Wait()
		if freeOS {
			debug.FreeOSMemory()
		}
		time.Sleep(2 * time.Second)
		if c%5 == 0 {
			stats(t, fmt.Sprintf("cycle %d", c))
		}
	}
}

func TestStandLikeThenGC(t *testing.T) {
	TestStandLike(t)
	runtime.GC()
	stats(t, "after 1 GC")
	runtime.GC()
	stats(t, "after 2 GC")
	debug.FreeOSMemory()
	time.Sleep(time.Second)
	stats(t, "freeOS")
}
