package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/servertest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
)

const testToken = "client-token"

// testKey is the target every test probes; its string form is what the spec
// §7 log line and the ?target= query must carry.
var testKey = proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"}

// fakeDiagnoser stands in for the xray child's stderr window (spec §5).
type fakeDiagnoser struct {
	match xray.Match
	ok    bool

	addr string
	port int
}

func (d *fakeDiagnoser) Diagnose(addr string, port int, _, _ time.Time) (xray.Match, bool) {
	d.addr, d.port = addr, port
	return d.match, d.ok
}

// probeFixture is a mon-server stub plus a prober that trusts it, the setup
// every case below starts from.
type probeFixture struct {
	stub   *servertest.Stub
	prober *Prober
	logs   *bytes.Buffer
}

func newFixture(t *testing.T) *probeFixture {
	t.Helper()
	stub := servertest.NewStub(t)
	stub.Approve("req-1", "mc-1", testToken)

	logs := &bytes.Buffer{}
	return &probeFixture{
		stub: stub,
		logs: logs,
		prober: &Prober{
			Logger:    slog.New(slog.NewTextHandler(logs, nil)),
			TLSConfig: stubTLS(t, stub),
		},
	}
}

// stubTLS extracts the httptest stub's certificate pool so the probe trusts
// it — production trusts the system CAs instead (spec §2).
func stubTLS(t *testing.T, stub *servertest.Stub) *tls.Config {
	t.Helper()
	tr, ok := stub.HTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("stub client transport is %T, want *http.Transport", stub.HTTPClient().Transport)
	}
	return tr.TLSClientConfig.Clone()
}

func (f *probeFixture) probeURL() string { return f.stub.URL() + "/v1/probe" }

// plan is a target's socks port plus the real server address the diagnoser is
// asked about (config.XrayPlan, step 3).
func plan(socksPort int) config.XrayPlan {
	return config.XrayPlan{
		Key:        config.TargetKey(testKey),
		SocksPort:  socksPort,
		InboundTag: "in-xray-12-proxy",
		ServerAddr: "real.example",
		ServerPort: 443,
	}
}

// fastBudgets keeps the package's tests to a few seconds: the phase that a
// case is about is short, the others are long enough not to fire first.
func fastBudgets() Budgets {
	return Budgets{Budget: 5 * time.Second, Connect: 2 * time.Second, TLS: 2 * time.Second, Headers: 2 * time.Second}
}

func TestProberXray_OK(t *testing.T) {
	f := newFixture(t)
	port := startSOCKS(t, true)

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(port), fastBudgets(), nil)

	if !res.Ok {
		t.Fatalf("probe failed: reason=%v detail=%v", deref(res.Reason), deref(res.Detail))
	}
	if res.ConnectMs == nil || res.TlsMs == nil || res.TtfbMs == nil {
		t.Errorf("phases not all measured: connect=%v tls=%v ttfb=%v", res.ConnectMs, res.TlsMs, res.TtfbMs)
	}
	if res.HandshakeMs != nil {
		t.Errorf("handshakeMs = %v, want nil for an xray probe", *res.HandshakeMs)
	}
	if res.EgressIp == nil || *res.EgressIp != "127.0.0.1" {
		t.Errorf("egressIp = %v, want the stub's view of the caller", res.EgressIp)
	}
	if res.Reason != nil || res.Detail != nil {
		t.Errorf("successful probe carries reason=%v detail=%v", deref(res.Reason), deref(res.Detail))
	}
	if got := f.logs.String(); !strings.Contains(got, "probe xray:12:proxy ok tls=") {
		t.Errorf("log line %q, want the spec §7 shape", got)
	}
	// The probe authenticates with the client token (protocol §5.2).
	reqs := f.stub.Requests()
	if len(reqs) == 0 {
		t.Fatal("stub saw no probe request")
	}
	if got := reqs[0].Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Errorf("Authorization = %q, want the client token", got)
	}
}

func TestProberXray_HTTPErrorOnForeignNonce(t *testing.T) {
	f := newFixture(t)
	f.stub.SetProbeNonce("not-the-nonce-we-sent")
	port := startSOCKS(t, true)

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(port), fastBudgets(), nil)

	assertFail(t, res, proto.ReasonHTTPError)
	if d := deref(res.Detail); !strings.Contains(d, "nonce mismatch") {
		t.Errorf("detail = %q, want the nonce mismatch", d)
	}
	if res.TlsMs == nil {
		t.Error("tlsMs not measured: the tunnel did carry the request")
	}
}

func TestProberXray_HTTPErrorOnRevokedToken(t *testing.T) {
	f := newFixture(t)
	f.stub.SetTokenStatus(http.StatusUnauthorized)
	port := startSOCKS(t, true)

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(port), fastBudgets(), nil)

	assertFail(t, res, proto.ReasonHTTPError)
	// Step 9's run loop reads the revocation out of this detail.
	if d := deref(res.Detail); !strings.Contains(d, "token_revoked") {
		t.Errorf("detail = %q, want mon-server's token_revoked code", d)
	}
}

func TestProberXray_TLSTimeoutWhenTunnelGoesSilent(t *testing.T) {
	f := newFixture(t)
	port := startSOCKS(t, false) // CONNECT succeeds, nothing is forwarded
	b := fastBudgets()
	b.TLS = 200 * time.Millisecond

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(port), b, nil)

	assertFail(t, res, proto.ReasonTLSTimeout)
	if res.TlsMs != nil {
		t.Errorf("tlsMs = %d, want nil for a handshake that never finished", *res.TlsMs)
	}
	if got := f.logs.String(); !strings.Contains(got, "probe xray:12:proxy FAIL tls_timeout") {
		t.Errorf("log line %q, want the spec §7 failure shape", got)
	}
}

func TestProberXray_TCPRefusedWhenSocksPortIsClosed(t *testing.T) {
	f := newFixture(t)

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(closedPort(t)), fastBudgets(), nil)

	assertFail(t, res, proto.ReasonTCPRefused)
}

func TestProberXray_ProbeTimeoutWhenServerNeverAnswers(t *testing.T) {
	f := newFixture(t)
	f.stub.HangNextProbes(1)
	port := startSOCKS(t, true)
	b := fastBudgets()
	b.Budget = 400 * time.Millisecond // the overall budget fires first

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(port), b, nil)

	assertFail(t, res, proto.ReasonProbeTimeout)
	if res.TlsMs == nil {
		t.Error("tlsMs not measured: the probe died after the handshake")
	}
}

func TestProberXray_RealityRealCertOverridesReason(t *testing.T) {
	f := newFixture(t)
	diag := &fakeDiagnoser{
		match: xray.Match{Reason: xray.ReasonRealityRealCert, Detail: "REALITY: received real certificate"},
		ok:    true,
	}

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(closedPort(t)), fastBudgets(), diag)

	assertFail(t, res, proto.ReasonRealityRealCert)
	if d := deref(res.Detail); d != "REALITY: received real certificate" {
		t.Errorf("detail = %q, want xray's own line", d)
	}
	if diag.addr != "real.example" || diag.port != 443 {
		t.Errorf("diagnosed %s:%d, want the plan's real server", diag.addr, diag.port)
	}
}

func TestProberXray_DetailFromDiagnoserIsTrimmed(t *testing.T) {
	f := newFixture(t)
	long := strings.Repeat("ошибка ", 200) // > 256 runes, multi-byte on purpose
	diag := &fakeDiagnoser{match: xray.Match{Detail: long}, ok: true}

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(closedPort(t)), fastBudgets(), diag)

	if got := len([]rune(deref(res.Detail))); got != MaxDetail {
		t.Errorf("detail is %d runes, want %d (protocol §5.3)", got, MaxDetail)
	}
	// A match without a reason leaves the classified one in place.
	if r := deref(res.Reason); r != proto.ReasonTCPRefused {
		t.Errorf("reason = %q, want the classified %q", r, proto.ReasonTCPRefused)
	}
}

func TestProberXray_NoDiagnoserIsAllowed(t *testing.T) {
	f := newFixture(t)

	res := f.prober.Xray(context.Background(), f.probeURL(), testToken, testKey, plan(closedPort(t)), fastBudgets(), nil)

	assertFail(t, res, proto.ReasonTCPRefused)
}

// assertFail checks the shape every failed result must have (protocol §5.3):
// ok false, the expected reason, and a non-empty detail of at most 256 runes.
func assertFail(t *testing.T, res proto.Result, wantReason string) {
	t.Helper()
	if res.Ok {
		t.Fatalf("probe succeeded, want failure %q", wantReason)
	}
	if res.Reason == nil || *res.Reason != wantReason {
		t.Fatalf("reason = %q, want %q (detail %q)", deref(res.Reason), wantReason, deref(res.Detail))
	}
	if res.Detail == nil || *res.Detail == "" {
		t.Error("failed probe carries no detail")
	}
	if n := len([]rune(deref(res.Detail))); n > MaxDetail {
		t.Errorf("detail is %d runes, want ≤ %d", n, MaxDetail)
	}
	if res.HandshakeMs != nil {
		t.Errorf("handshakeMs = %d, want nil for an xray probe", *res.HandshakeMs)
	}
	if res.EgressIp != nil {
		t.Errorf("egressIp = %q on a failed probe", *res.EgressIp)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
