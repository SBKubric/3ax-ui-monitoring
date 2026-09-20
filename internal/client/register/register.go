// Package register implements mon-client's registration flow (spec §3,
// protocol §2): mint a pairing code, submit a registration request, and
// poll it until an operator approves or rejects it in the admin UI — or
// until it expires and mon-client has to try again with a fresh code.
//
// Run is the package's only real entry point; everything else here is a
// helper Run uses or a type its Deps needs. It blocks the calling
// goroutine until it has a state.File to show for it or ctx ends, which is
// exactly what cmd/mon-client wants: "no state file" means "nothing else
// can happen until this returns".
package register

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// pairingCodeAlphabet is spec §3's `[A-Z2-9]` — every uppercase letter plus
// the digits that are hard to confuse with letters or with each other over
// the phone/chat an operator reads a pairing code back over (0/O and 1/I
// are excluded by the digit range itself, not by anything this package
// does).
const pairingCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789"

// pairingCodeLength is spec §3's fixed code length.
const pairingCodeLength = 6

// NewPairingCode draws a fresh spec §3 pairing code from r (production:
// crypto/rand.Reader; a test may hand in a fixed byte stream to pin the
// generated code). Selection is unbiased: rather than `byte % len(alphabet)`,
// which would make the first `256 % len(alphabet)` letters of the alphabet
// very slightly more likely, it rejects any byte that would not divide
// evenly and draws again — the standard fix for mapping a random byte onto
// an alphabet whose length does not evenly divide 256.
func NewPairingCode(r io.Reader) (string, error) {
	const n = len(pairingCodeAlphabet)
	// limit is the largest multiple of n that fits in a byte; a byte drawn
	// at or above it is discarded and redrawn so every one of the n
	// symbols is equally likely.
	const limit = 256 - (256 % n)

	buf := make([]byte, 1)
	code := make([]byte, pairingCodeLength)
	for i := range code {
		for {
			if _, err := io.ReadFull(r, buf); err != nil {
				return "", fmt.Errorf("register: read random byte: %w", err)
			}
			if int(buf[0]) < limit {
				code[i] = pairingCodeAlphabet[int(buf[0])%n]
				break
			}
		}
	}
	return string(code), nil
}

// Deps are Run's dependencies. Every field with a zero value gets a
// production-sensible default (see fillDefaults) so a caller only has to
// supply what it actually wants to control — a test overrides Clock, Sleep
// and Rand to run the whole flow, backoff included, without a single real
// timer tick.
type Deps struct {
	// API is the mon-server client Register/Poll are called through.
	API *api.Client
	// State is where an approved registration is saved (spec §3.2).
	State *state.Dir
	// Clock is used only to compare against a registration request's
	// expiresAt (spec §3.2's local 410 detection) — never for anything
	// else, since every actual wait goes through Sleep.
	Clock clock.Clock
	// Sleep waits for d or returns ctx.Err() if ctx ends first. The zero
	// value is a real timer (defaultSleep); tests inject a recorder that
	// also advances the fake Clock, so a backoff table test runs to
	// completion instantly instead of waiting on the wall clock.
	Sleep func(ctx context.Context, d time.Duration) error
	// Log receives the pairing-code line (spec §7) and Run's other
	// human-readable progress lines. The zero value is slog.Default().
	Log *slog.Logger
	// Hostname and Version go into every RegisterRequest verbatim
	// (protocol §2.1).
	Hostname string
	Version  string
	// PublicIP is called once per registration attempt for the request's
	// publicIp field (protocol §2.1: "best effort", empty is fine). A nil
	// PublicIP always yields "". See PublicIPFromDial for the production
	// implementation.
	PublicIP func(ctx context.Context) string
	// Rand feeds NewPairingCode. The zero value is crypto/rand.Reader.
	Rand io.Reader
}

// fillDefaults returns a copy of d with every zero-valued field replaced by
// its production default, so the rest of this package never has to nil-check.
func (d Deps) fillDefaults() Deps {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	if d.Sleep == nil {
		d.Sleep = defaultSleep
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Rand == nil {
		d.Rand = rand.Reader
	}
	return d
}

// publicIP calls d.PublicIP if set, else reports "" — the "best effort,
// empty is fine" half of protocol §2.1.
func (d Deps) publicIP(ctx context.Context) string {
	if d.PublicIP == nil {
		return ""
	}
	return d.PublicIP(ctx)
}

// defaultSleep is Deps.Sleep's zero-value behaviour: an ordinary
// cancellable timer.
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

// Backoff steps and the fixed rejected-request wait, spec §3.2/§3.3: "410
// → новая заявка с новым кодом, backoff 1 → 2 → 5 мин, дальше каждые 5
// мин" and "rejected → ждать 1 ч, новая заявка".
var backoffSteps = []time.Duration{1 * time.Minute, 2 * time.Minute, 5 * time.Minute}

const rejectedWait = 1 * time.Hour

// defaultPollAfter is used when a 202's pollAfter is missing or zero
// (issue #16: "опрос ... каждые pollAfter до ... (default 10 s if 0)").
const defaultPollAfter = 10 * time.Second

// backoff is one escalating counter over spec §3.2's "1 → 2 → 5 мин,
// дальше каждые 5 мин" sequence. Run keeps two of them, because the two
// things that can go wrong during a registration are unrelated failures
// and must not share a streak:
//
//   - expiry — the request was filed and then expired (a 410, or this
//     box's own clock reaching expiresAt). Consecutive expiries keep
//     climbing: nobody is approving this box, so asking again ever more
//     slowly is the point of the ladder.
//   - transient — Register or Poll did not get an answer at all (network
//     error, 5xx, 429). This streak is over the moment mon-server answers:
//     a request that was accepted (202) proves the link works, so the next
//     hiccup starts again at one minute rather than inheriting the wait of
//     an outage that is already over.
//
// A rejected request resets both (see Run): the operator has seen this box
// and said no, the fixed hour of spec §3.2 is the whole wait, and whatever
// went wrong before that is ancient history.
type backoff struct {
	idx int
}

// delay is the wait this step of the sequence uses, capped at the last
// (5-minute) step once idx runs past the end.
func (b *backoff) delay() time.Duration {
	i := b.idx
	if i >= len(backoffSteps) {
		i = len(backoffSteps) - 1
	}
	return backoffSteps[i]
}

// advance moves to the next step (idempotently capped by delay once there).
func (b *backoff) advance() { b.idx++ }

// reset puts the ladder back on its first step, for the streak-ending
// events described on the type.
func (b *backoff) reset() { b.idx = 0 }

// waitFor picks the wait for a failed Register/Poll call: a 429's own
// Retry-After when it carries one (protocol §2.1), else the current
// backoff step (issue #16: "429 → wait Retry-After (fallback: the current
// backoff step)"). Every other retryable error (network, 5xx) always uses
// the backoff step.
func (b *backoff) waitFor(err error) time.Duration {
	var rl *api.RateLimitError
	if errors.As(err, &rl) && rl.RetryAfter > 0 {
		return rl.RetryAfter
	}
	return b.delay()
}

// Run drives the whole registration flow (spec §3) to completion: mint a
// code, submit it, poll until approved, save state.json, and return it.
// It never returns until that happens or ctx ends — cmd/mon-client's `run`
// command has nothing useful to do before a mon-client has a token, so
// blocking here is exactly right rather than something to work around with
// a background goroutine.
func Run(ctx context.Context, deps Deps) (*state.File, error) {
	d := deps.fillDefaults()
	transient := &backoff{}
	expiry := &backoff{}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		code, err := NewPairingCode(d.Rand)
		if err != nil {
			return nil, err
		}

		reg, err := submitRegister(ctx, d, code, transient)
		if err != nil {
			return nil, err
		}
		// Spec §7: the exact line an operator reads off the box's console
		// to know which code to type into the admin UI.
		d.Log.Info(fmt.Sprintf("registration request sent, pairing code %s", code))

		outcome, err := pollUntilResolved(ctx, d, reg, transient, expiry)
		if err != nil {
			return nil, err
		}

		switch outcome.status {
		case statusApproved:
			f := &state.File{
				MonClientID: outcome.monClientID,
				Token:       outcome.token,
				ServerURL:   d.API.BaseURL,
				// AppliedRevision starts empty: this box has not applied
				// any config yet (step 4 fetches and applies one).
				AppliedRevision: "",
			}
			if err := d.State.Save(f); err != nil {
				return nil, fmt.Errorf("register: save state: %w", err)
			}
			return f, nil
		case statusRejected:
			// Spec §3.2: wait a fixed hour, then file a wholly new request
			// (new code) — not part of the escalating backoff at all. The
			// ladders start over with it: the next request is a fresh
			// attempt at being adopted, not the continuation of a streak.
			transient.reset()
			expiry.reset()
			if err := d.Sleep(ctx, rejectedWait); err != nil {
				return nil, err
			}
		case statusExpired:
			// Backoff/new-code handling already happened inside
			// pollUntilResolved; just loop to submit the next request.
		}
	}
}

// submitRegister calls Register, retrying under the shared backoff on any
// retryable failure (network error, 5xx, 429) until it succeeds or ctx
// ends. It never abandons the pairing code it was given — a failed POST
// never reached mon-server, so there is nothing to supersede yet, and
// printing a second, different code to the log before the first one was
// even accepted would only confuse the operator reading the console.
func submitRegister(ctx context.Context, d Deps, code string, bo *backoff) (*proto.RegisterResponse, error) {
	req := proto.RegisterRequest{
		PairingCode: code,
		Hostname:    d.Hostname,
		Version:     d.Version,
	}
	for {
		req.PublicIP = d.publicIP(ctx)
		resp, err := d.API.Register(ctx, req)
		if err == nil {
			// Accepted (202): mon-server is reachable, so whatever streak
			// of transport failures preceded this is over.
			bo.reset()
			return resp, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		wait := bo.waitFor(err)
		bo.advance()
		// Spec §7: without this line a box whose POST /v1/register keeps
		// failing prints nothing at all — no pairing code, no error — and
		// an operator watching `docker logs` has no way to tell a
		// mon-client that cannot reach mon-server from one that is simply
		// slow to start.
		d.Log.Warn(fmt.Sprintf("registration request failed: %v, retrying in %s", err, wait))
		if err := d.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// pollStatus is the resolved outcome of a poll loop (as distinct from
// proto.PollResponse's wire "pending", which never leaves this function —
// pending just means "loop again").
type pollStatus int

const (
	statusApproved pollStatus = iota
	statusRejected
	statusExpired
)

// pollOutcome is what pollUntilResolved hands back to Run.
type pollOutcome struct {
	status      pollStatus
	monClientID string
	token       string
}

// pollUntilResolved polls one registration request (protocol §2.2) until
// it is approved, rejected, or expires — either because mon-server said
// 410 or because this box's own clock reached the expiresAt the 202
// carried first (issue #16: "expiresAt reached locally → treat as 410",
// which matters when the network is down for long enough that mon-client
// never even gets the 410 itself). A transport error or 5xx on the poll
// call never abandons the request — it just waits out the backoff and
// polls the same requestId again, since the request itself is still alive
// on mon-server's side for up to its 5-minute TTL (protocol §2.1).
func pollUntilResolved(ctx context.Context, d Deps, reg *proto.RegisterResponse, transient, expiry *backoff) (*pollOutcome, error) {
	pollAfter := time.Duration(reg.PollAfterMs) * time.Millisecond
	if pollAfter <= 0 {
		pollAfter = defaultPollAfter
	}
	expiresAt := time.UnixMilli(reg.ExpiresAt).UTC()

	wait := pollAfter
	for {
		if err := d.Sleep(ctx, wait); err != nil {
			return nil, err
		}

		if !d.Clock.Now().Before(expiresAt) {
			return expireLocally(ctx, d, expiry)
		}

		resp, err := d.API.Poll(ctx, reg.RequestID)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			if errors.Is(err, api.ErrRequestExpired) {
				return expireLocally(ctx, d, expiry)
			}
			wait = transient.waitFor(err)
			transient.advance()
			continue
		}
		// An answer, whatever it says: the transport streak is over.
		transient.reset()

		switch resp.Status {
		case "approved":
			return &pollOutcome{status: statusApproved, monClientID: resp.MonClientID, token: resp.Token}, nil
		case "rejected":
			return &pollOutcome{status: statusRejected}, nil
		default:
			// "pending", or anything mon-server might add later
			// (protocol §1's forward-compatibility rule) — keep polling
			// on the normal cadence.
			wait = pollAfter
		}
	}
}

// expireLocally applies the 410 backoff (spec §3.2, the expiry ladder) and
// reports statusExpired,
// shared by both the explicit-410 and locally-detected-expiry paths so
// they behave identically.
func expireLocally(ctx context.Context, d Deps, bo *backoff) (*pollOutcome, error) {
	wait := bo.delay()
	bo.advance()
	if err := d.Sleep(ctx, wait); err != nil {
		return nil, err
	}
	return &pollOutcome{status: statusExpired}, nil
}

// PublicIPFromDial returns a Deps.PublicIP implementation that opens a TCP
// connection to serverURL's host (defaulting to port 443 when the URL
// carries none) and reports the local address the kernel chose for it —
// which, for a box with a single default route, is that box's outbound
// public IP as far as the destination is concerned (spec §3: "publicIp —
// best effort, из первого исходящего соединения"). It never blocks past
// ctx and reports "" on any error rather than failing registration over a
// field the protocol already says is optional.
func PublicIPFromDial(serverURL string) func(ctx context.Context) string {
	return func(ctx context.Context) string {
		u, err := url.Parse(serverURL)
		if err != nil {
			return ""
		}
		host := u.Hostname()
		if host == "" {
			return ""
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}

		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return ""
		}
		defer func() { _ = conn.Close() }()

		addr, ok := conn.LocalAddr().(*net.TCPAddr)
		if !ok {
			return ""
		}
		return addr.IP.String()
	}
}
