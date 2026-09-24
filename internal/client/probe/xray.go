package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
)

// Diagnoser is the probe's read-only view of the xray child's stderr
// (spec §5): after a failed probe it is asked what xray said about this
// target inside the probe's own time window. *xray.Process satisfies it, and
// nil is allowed — a mon-client whose xray never started still probes, it just
// cannot explain the failures any better than Classify does.
type Diagnoser interface {
	Diagnose(target xray.Target, since, until time.Time) (xray.Match, bool)
}

// Prober runs single probes. It exists only to carry the collaborators a
// probe cannot make up for itself — the logger every probe result is written
// to (spec §7) and, for tests, the TLS trust to use toward mon-server — so
// that the probe functions stay pure otherwise. The zero value works and logs
// through slog.Default(); the cycle runner (step 7) builds one per run loop.
type Prober struct {
	// Logger receives one line per probe in the spec §7 shapes. nil means
	// slog.Default(), matching xray.New's convention.
	Logger *slog.Logger
	// TLSConfig, when set, is the transport's TLS configuration toward
	// mon-server. Production leaves it nil: spec §2 says a mon-client trusts
	// the system CAs and pins nothing. It exists so tests can trust the
	// httptest stub's self-signed certificate without a global CA pool.
	TLSConfig *tls.Config
}

// Xray probes one xray-target through its loopback socks inbound (spec §5,
// research §6.1) and returns the protocol's result for the cycle.
//
// Everything about the tunnel is in the transport: Proxy =
// socks5://127.0.0.1:<plan.SocksPort>, so the TCP dial httptrace measures is
// to loopback (connectMs ≈ 0) while the TLS handshake carries the whole
// tunnel — Reality handshake, real server → mon-server TCP, TLS 1.3 — which
// is why tlsMs is this probe's latency signal. handshakeMs stays null: only
// the AWG probe (step 6) has a handshake event to timestamp.
//
// On failure the reason comes from Classify and is then given to the xray
// child for a second opinion: a Reality handshake that got a real certificate
// looks like an ordinary timeout from the outside, and only xray's stderr
// names it (spec §5, research §2.4). A match's detail always wins over the Go
// error text, because xray's own line says more about the tunnel than
// "context deadline exceeded" ever can.
//
// The probe never returns an error: a failed probe is a result, and the cycle
// must carry one line per target no matter what happened.
func (p *Prober) Xray(ctx context.Context, probeURL, token string, key proto.TargetKey, plan config.XrayPlan, b Budgets, diag Diagnoser) proto.Result {
	res := proto.Result{TargetKey: key}

	proxy, err := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(plan.SocksPort))
	if err != nil { // unreachable for a numeric port, but a bad plan must not panic a cycle
		return p.fail(res, proto.ReasonTCPRefused, trim(err.Error()), Phases{})
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxy),
		TLSClientConfig: p.TLSConfig,
	}
	defer transport.CloseIdleConnections()

	// time.Now() here is the same sanctioned exception Do documents: the
	// window handed to Diagnose must line up with the wall-clock timestamps
	// xray's stderr reader stamped on its lines.
	start := time.Now()
	ph, echo, err := Do(ctx, transport, probeURL, token, key, b)
	end := time.Now()

	res.ConnectMs, res.TlsMs, res.TtfbMs = ph.ConnectMs, ph.TlsMs, ph.TtfbMs
	if err == nil {
		res.Ok = true
		egress := echo.EgressIp
		res.EgressIp = &egress
		p.log().Info(fmt.Sprintf("probe %s ok tls=%s ttfb=%s", key, msText(ph.TlsMs), msText(ph.TtfbMs)))
		return res
	}

	reason, detail := Classify(err, ph, b)
	if diag != nil {
		target := xray.Target{OutboundTag: plan.OutboundTag, Addr: plan.ServerAddr, Port: plan.ServerPort}
		if m, ok := diag.Diagnose(target, start, end); ok {
			if m.Reason == xray.ReasonRealityRealCert {
				reason = proto.ReasonRealityRealCert
			}
			if m.Detail != "" {
				detail = trim(m.Detail)
			}
		}
	}
	return p.fail(res, reason, detail, ph)
}

// fail stamps a failed result and writes its spec §7 log line.
func (p *Prober) fail(res proto.Result, reason, detail string, ph Phases) proto.Result {
	res.Ok = false
	res.ConnectMs, res.TlsMs, res.TtfbMs = ph.ConnectMs, ph.TlsMs, ph.TtfbMs
	res.Reason, res.Detail = &reason, &detail
	p.log().Info(fmt.Sprintf("probe %s FAIL %s %s", res.TargetKey, reason, detail))
	return res
}

// log is the logger to use, defaulting to slog.Default() so a zero Prober is
// still usable (xray.New has the same convention).
func (p *Prober) log() *slog.Logger {
	if p.Logger == nil {
		return slog.Default()
	}
	return p.Logger
}

// msText renders a phase for the log line (spec §7: "tls=47ms"), showing an
// unmeasured phase as "-" rather than a misleading 0.
func msText(ms *int64) string {
	if ms == nil {
		return "-"
	}
	return strconv.FormatInt(*ms, 10) + "ms"
}
