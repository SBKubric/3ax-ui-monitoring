package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

const (
	// nonceBytes is the probe nonce's length before encoding (spec §5: "16
	// байт base64url на пробу"). A fresh nonce per probe is what makes a
	// reply provably *this* probe's reply and not a cached or replayed one.
	nonceBytes = 16

	// MaxDetail caps a result's detail (protocol §5.3, spec §5: "≤ 256
	// символов"). Counted in runes: error texts carry hostnames and xray's
	// own messages, and a byte cut could split a multi-byte character.
	MaxDetail = 256
)

// Phases are the wall-clock phases httptrace measured for one probe
// (research §6.1). Every field is nil until its phase actually happened, so a
// probe that died in the TCP dial reports connectMs and nothing else — which
// is exactly what the heartbeat should carry, and what Classify reads to tell
// a hung TLS handshake from a hung tunnel.
type Phases struct {
	// ConnectMs is ConnectStart→ConnectDone: for an xray probe the TCP dial
	// to the loopback socks port (≈ 0), for AWG the dial through netstack.
	ConnectMs *int64
	// TlsMs is TLSHandshakeStart→TLSHandshakeDone — the first end-to-end
	// phase through the tunnel (research §6.1), i.e. the tunnel's latency.
	TlsMs *int64
	// TtfbMs is WroteRequest→GotFirstResponseByte: one round trip through the
	// tunnel plus mon-server's own handling.
	TtfbMs *int64
}

// NonceMismatchError is a 200 that echoed a different nonce than the one this
// probe sent (spec §5: "чужой nonce" is an http_error). It is a typed error
// rather than a string so Classify can recognise it without parsing, and so a
// caller debugging a captive portal can see both nonces.
type NonceMismatchError struct {
	Want string
	Got  string
}

func (e *NonceMismatchError) Error() string {
	return fmt.Sprintf("probe: nonce mismatch: sent %q, got %q", e.Want, e.Got)
}

// HTTPStatusError is any non-200 answer from /v1/probe (spec §5: http_error).
// Body is mon-server's error document truncated to MaxDetail, because that is
// where the machine-readable code lives — a revoked token, for instance,
// shows up as token_revoked in the detail of every probe result, which is how
// the run loop (step 9) notices a revocation even between heartbeats.
type HTTPStatusError struct {
	Status int
	Body   string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("probe: unexpected status %d", e.Status)
	}
	return fmt.Sprintf("probe: unexpected status %d: %s", e.Status, e.Body)
}

// Do runs exactly one tunnel probe over the transport it is given and returns
// its phases, the echo, and the error that stopped it (protocol §5.2).
//
// The transport is the caller's choice of tunnel — Prober.Xray hands it one
// with a socks5 Proxy, the AWG probe (step 6) one with a netstack DialContext
// — and Do fills in everything that must be true of *any* probe transport:
// no connection reuse (a reused connection has no connect/TLS phase at all,
// research §5), and the three phase timeouts from Budgets. The whole call
// runs under context.WithTimeout(ctx, b.Budget).
//
// Success is a 200 whose body echoes the nonce this call generated; anything
// else is an error: *NonceMismatchError or *HTTPStatusError for an answer we
// got and did not like, whatever the transport produced otherwise. Phases are
// returned in every case, including failures — a probe that got through TLS
// and then timed out still measured the tunnel.
//
// Timing here is deliberately `time.Now()` and not clock.Clock (brief §1):
// these are wall-clock measurements of real network phases reported to
// mon-server as latency, so a fake clock would not make them testable, it
// would make them wrong. This is the one sanctioned exception in
// internal/client.
func Do(ctx context.Context, transport *http.Transport, probeURL, token string, key proto.TargetKey, b Budgets) (Phases, *proto.ProbeEcho, error) {
	nonce, err := newNonce()
	if err != nil {
		return Phases{}, nil, fmt.Errorf("probe: nonce: %w", err)
	}
	target, err := probeRequestURL(probeURL, key, nonce)
	if err != nil {
		return Phases{}, nil, err
	}

	transport.DisableKeepAlives = true
	transport.TLSHandshakeTimeout = b.TLS
	transport.ResponseHeaderTimeout = b.Headers
	transport.DialContext = (&net.Dialer{Timeout: b.Connect}).DialContext

	ctx, cancel := context.WithTimeout(ctx, b.Budget)
	defer cancel()

	tr := newTracer()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, tr.trace()), http.MethodGet, target, nil)
	if err != nil {
		return Phases{}, nil, fmt.Errorf("probe: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return tr.phases(), nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return tr.phases(), nil, &HTTPStatusError{Status: resp.StatusCode, Body: trim(string(body))}
	}

	var echo proto.ProbeEcho
	if err := json.Unmarshal(body, &echo); err != nil {
		// A 200 we cannot read is an http_error just like a wrong nonce: the
		// tunnel worked, the answer did not.
		return tr.phases(), nil, &HTTPStatusError{Status: resp.StatusCode, Body: trim("malformed echo: " + string(body))}
	}
	if echo.Nonce != nonce {
		return tr.phases(), nil, &NonceMismatchError{Want: nonce, Got: echo.Nonce}
	}
	return tr.phases(), &echo, nil
}

// probeRequestURL builds `<probeUrl>?target=<kind:inboundId:path>&n=<nonce>`
// (protocol §5.2) on top of whatever query the document's probeUrl already
// carried, rather than string-concatenating a "?" that may be a second one.
func probeRequestURL(probeURL string, key proto.TargetKey, nonce string) (string, error) {
	u, err := url.Parse(probeURL)
	if err != nil {
		return "", fmt.Errorf("probe: bad probeUrl %q: %w", probeURL, err)
	}
	q := u.Query()
	q.Set("target", key.String())
	q.Set("n", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// newNonce draws the probe's nonce (spec §5: 16 random bytes, base64url).
func newNonce() (string, error) {
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// tracer collects the httptrace timestamps of one probe. The hooks fire on
// the transport's own goroutines (GotFirstResponseByte in particular), so the
// timestamps are taken under a mutex — the alternative, racing on plain
// fields, is only invisible because a test rarely loses that race.
type tracer struct {
	mu                          sync.Mutex
	connectStart, connectDone   time.Time
	tlsStart, tlsDone           time.Time
	wroteRequest, firstResponse time.Time
}

func newTracer() *tracer { return &tracer{} }

func (t *tracer) trace() *httptrace.ClientTrace {
	stamp := func(dst *time.Time) {
		t.mu.Lock()
		defer t.mu.Unlock()
		if dst.IsZero() {
			*dst = time.Now()
		}
	}
	// A phase that ended in an error is left unmeasured: its duration is the
	// timeout that killed it, not a latency, and reporting it as one would
	// make a dead tunnel look like a slow but working tunnel in the panel's
	// statistics (protocol §5.3: an unmeasured phase is null).
	return &httptrace.ClientTrace{
		ConnectStart: func(string, string) { stamp(&t.connectStart) },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				stamp(&t.connectDone)
			}
		},
		TLSHandshakeStart: func() { stamp(&t.tlsStart) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				stamp(&t.tlsDone)
			}
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { stamp(&t.wroteRequest) },
		GotFirstResponseByte: func() { stamp(&t.firstResponse) },
	}
}

// phases turns the collected timestamps into the protocol's millisecond
// fields, leaving a phase nil when it never completed (research §6.1).
func (t *tracer) phases() Phases {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Phases{
		ConnectMs: span(t.connectStart, t.connectDone),
		TlsMs:     span(t.tlsStart, t.tlsDone),
		TtfbMs:    span(t.wroteRequest, t.firstResponse),
	}
}

// span is the millisecond distance between two trace stamps, or nil when the
// phase did not finish.
func span(from, to time.Time) *int64 {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return nil
	}
	ms := to.Sub(from).Milliseconds()
	return &ms
}

// trim cuts a string to MaxDetail runes (protocol §5.3).
func trim(s string) string {
	r := []rune(s)
	if len(r) <= MaxDetail {
		return s
	}
	return string(r[:MaxDetail])
}
