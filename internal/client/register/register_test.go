package register

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/servertest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// --- NewPairingCode ------------------------------------------------------

// TestNewPairingCode_Format checks the code matches spec §3's
// `[A-Z2-9]{6}` exactly, over many draws from the real crypto/rand source.
func TestNewPairingCode_Format(t *testing.T) {
	re := regexp.MustCompile(`^[A-Z2-9]{6}$`)
	for i := 0; i < 200; i++ {
		code, err := NewPairingCode(rand.Reader)
		if err != nil {
			t.Fatalf("NewPairingCode: %v", err)
		}
		if !re.MatchString(code) {
			t.Fatalf("code %q does not match %s", code, re)
		}
	}
}

// TestNewPairingCode_UnbiasedRejection checks that a byte at or above the
// rejection threshold is discarded and redrawn rather than folded in via
// modulo, by feeding a reader that yields one rejected byte before a good
// one and checking the result only reflects the good byte.
func TestNewPairingCode_UnbiasedRejection(t *testing.T) {
	// len(alphabet) = 34; limit = 256 - (256 % 34) = 238. 255 must be
	// rejected; the next byte (0 -> 'A') must be used instead.
	src := bytes.Repeat([]byte{255, 0}, pairingCodeLength)
	code, err := NewPairingCode(bytes.NewReader(src))
	if err != nil {
		t.Fatalf("NewPairingCode: %v", err)
	}
	if want := "AAAAAA"; code != want {
		t.Fatalf("code = %q, want %q (255 should have been rejected)", code, want)
	}
}

// TestNewPairingCode_ShortReaderErrors checks a reader that runs out of
// bytes produces an error rather than a short/garbage code.
func TestNewPairingCode_ShortReaderErrors(t *testing.T) {
	if _, err := NewPairingCode(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected an error from an empty reader")
	}
}

// --- test scaffolding ------------------------------------------------------

// syncSleep is a Deps.Sleep that never actually waits: it records the
// requested duration and advances fc by it, so a whole registration flow
// (backoff included) runs to completion in test time rather than wall
// time, per issue #16's "recording Sleep + Fake clock (no real waiting)".
// It still honours ctx cancellation, since Run's promptness on ctx end is
// itself under test.
func syncSleep(fc *clock.Fake) (sleep func(ctx context.Context, d time.Duration) error, waits func() []time.Duration) {
	var mu sync.Mutex
	var log []time.Duration
	sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		mu.Lock()
		log = append(log, d)
		mu.Unlock()
		fc.Advance(d)
		return nil
	}
	waits = func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), log...)
	}
	return sleep, waits
}

// newTestDeps wires Deps to stub, a fresh state.Dir under t.TempDir(), a
// fake clock seeded at an arbitrary but fixed instant, and a log buffer a
// test can grep.
func newTestDeps(t *testing.T, stub *servertest.Stub) (Deps, *clock.Fake, *bytes.Buffer, func() []time.Duration) {
	t.Helper()
	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	// Seeded far in the past relative to real wall-clock time: the stub
	// computes expiresAt from real time.Now() (protocol §2.1's 5-minute
	// TTL), and syncSleep advances this fake clock by every duration Run
	// waits out — keeping it far behind means the sum of a test's ordinary
	// pollAfter/backoff waits can never accidentally cross a real
	// expiresAt and trigger the local-expiry path by surprise.
	// TestRun_LocalExpiryTreatsAsExpired deliberately overrides this to
	// test that path on purpose.
	fc := clock.NewFake(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	sleep, waits := syncSleep(fc)
	var logBuf bytes.Buffer
	d := Deps{
		API:      api.New(stub.URL(), stub.HTTPClient()),
		State:    dir,
		Clock:    fc,
		Sleep:    sleep,
		Log:      slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Hostname: "vps-ams-1",
		Version:  "0.1.0",
		Rand:     rand.Reader,
	}
	return d, fc, &logBuf, waits
}

// pendingRequestID polls the stub's recorded requests until a GET
// /v1/register/<id> shows up and returns <id> — the only way a test can
// learn the requestId Run generated internally, since the stub only ever
// hands it back inside the (unobserved, from here) 202 response body.
func pendingRequestID(t *testing.T, stub *servertest.Stub) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, req := range stub.Requests() {
			if req.Method == "GET" && strings.HasPrefix(req.Path, "/v1/register/") {
				return strings.TrimPrefix(req.Path, "/v1/register/")
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a poll request")
	return ""
}

// --- Run: approved -----------------------------------------------------

// TestRun_Approved checks the full happy path: the pairing code is logged
// before the first poll, and once the stub approves the request, Run saves
// state.json with the issued id/token and this Client's BaseURL.
func TestRun_Approved(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, logBuf, _ := newTestDeps(t, stub)

	type result struct {
		f   *state.File
		err error
	}
	resCh := make(chan result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		f, err := Run(ctx, d)
		resCh <- result{f, err}
	}()

	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "sekret-token")

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("Run: %v", res.err)
		}
		if res.f.MonClientID != "ams-1" || res.f.Token != "sekret-token" {
			t.Fatalf("state = %+v, want monClientId=ams-1 token=sekret-token", res.f)
		}
		if res.f.ServerURL != stub.URL() {
			t.Fatalf("ServerURL = %q, want %q", res.f.ServerURL, stub.URL())
		}
		if res.f.AppliedRevision != "" {
			t.Fatalf("AppliedRevision = %q, want empty", res.f.AppliedRevision)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after approval")
	}

	// spec §7's exact log line, with the code that was actually sent.
	re := regexp.MustCompile(`registration request sent, pairing code [A-Z2-9]{6}`)
	if !re.MatchString(logBuf.String()) {
		t.Fatalf("log = %q, want it to contain the pairing-code line", logBuf.String())
	}

	// the saved state file really is on disk, readable back.
	saved, err := d.State.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.Token != "sekret-token" {
		t.Fatalf("saved token = %q, want sekret-token", saved.Token)
	}
}

// --- Run: rejected -------------------------------------------------------

// TestRun_RejectedWaitsAnHourThenRetriesWithNewCode checks spec §3.2's
// rejected path: a fixed hour wait (not part of the escalating backoff),
// then a wholly new request with a different pairing code (issue #16:
// "повторная заявка использует новый код").
func TestRun_RejectedWaitsAnHourThenRetriesWithNewCode(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, logBuf, waits := newTestDeps(t, stub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	firstID := pendingRequestID(t, stub)
	stub.Reject(firstID)

	// Wait until the hour-long wait has actually been recorded before
	// approving the second request, so this test also pins the wait's
	// duration rather than only its eventual outcome.
	deadline := time.Now().Add(5 * time.Second)
	sawHourWait := false
	for time.Now().Before(deadline) && !sawHourWait {
		for _, w := range waits() {
			if w == rejectedWait {
				sawHourWait = true
			}
		}
		time.Sleep(time.Millisecond)
	}
	if !sawHourWait {
		t.Fatalf("never observed the 1h rejected-wait; waits so far: %v", waits())
	}

	secondID := waitForNewRequestID(t, stub, map[string]bool{firstID: true})
	stub.Approve(secondID, "ams-1", "tok2")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the second approval")
	}

	codes := regexp.MustCompile(`pairing code ([A-Z2-9]{6})`).FindAllStringSubmatch(logBuf.String(), -1)
	if len(codes) < 2 {
		t.Fatalf("expected at least 2 pairing-code log lines, got %d: %q", len(codes), logBuf.String())
	}
	if codes[0][1] == codes[1][1] {
		t.Fatalf("both requests logged the same pairing code %q", codes[0][1])
	}
}

// --- Run: 410 / expiry backoff -------------------------------------------

// TestRun_ExpiredBackoffSequence drives four consecutive 410s (explicit
// Expire calls) and checks the backoff sequence between them is exactly
// 1, 2, 5, 5 minutes (spec §3.2), before finally approving the fifth
// request to let Run return.
func TestRun_ExpiredBackoffSequence(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		id := waitForNewRequestID(t, stub, seen)
		stub.Expire(id)
	}
	lastID := waitForNewRequestID(t, stub, seen)
	stub.Approve(lastID, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the final approval")
	}

	backoffWaits := filterBackoffWaits(waits())
	want := []time.Duration{1 * time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if len(backoffWaits) < len(want) {
		t.Fatalf("backoff waits = %v, want at least %v", backoffWaits, want)
	}
	for i, w := range want {
		if backoffWaits[i] != w {
			t.Fatalf("backoff step %d = %v, want %v (all: %v)", i, backoffWaits[i], w, backoffWaits)
		}
	}
}

// waitForRegisterPost waits for at least one POST /v1/register to have
// been recorded — near-instant, unlike pendingRequestID, since it does not
// wait out any pollAfter delay first.
func waitForRegisterPost(t *testing.T, stub *servertest.Stub) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, req := range stub.Requests() {
			if req.Method == "POST" && req.Path == "/v1/register" {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a register request")
}

// waitForNewRequestID waits for a poll request whose id is not already in
// seen, adds it, and returns it.
func waitForNewRequestID(t *testing.T, stub *servertest.Stub, seen map[string]bool) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, req := range stub.Requests() {
			if req.Method != "GET" || !strings.HasPrefix(req.Path, "/v1/register/") {
				continue
			}
			id := strings.TrimPrefix(req.Path, "/v1/register/")
			if !seen[id] {
				seen[id] = true
				return id
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a new poll request")
	return ""
}

// filterBackoffWaits drops the ordinary pollAfter (10s) waits, leaving
// only the ones that came from the backoff sequence.
func filterBackoffWaits(all []time.Duration) []time.Duration {
	var out []time.Duration
	for _, w := range all {
		if w != defaultPollAfter {
			out = append(out, w)
		}
	}
	return out
}

// --- Run: 429 on register --------------------------------------------------

// TestRun_RegisterRateLimitHonoursRetryAfter checks a 429 on submitting
// the request waits exactly the header's Retry-After, not the backoff
// step.
func TestRun_RegisterRateLimitHonoursRetryAfter(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)
	stub.RegisterStatus(429, 3*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	// Let at least one 429 happen, then let registration through.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(waits()) == 0 {
		time.Sleep(time.Millisecond)
	}
	stub.RegisterStatus(0, 0)

	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	found := false
	for _, w := range waits() {
		if w == 3*time.Second {
			found = true
		}
	}
	if !found {
		t.Fatalf("waits = %v, want one of them to be the 3s Retry-After", waits())
	}
}

// TestRun_RegisterRateLimitFallsBackToBackoff checks a 429 with no
// Retry-After header falls back to the current backoff step (issue #16).
func TestRun_RegisterRateLimitFallsBackToBackoff(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)
	stub.RegisterStatus(429, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(waits()) == 0 {
		time.Sleep(time.Millisecond)
	}
	stub.RegisterStatus(0, 0)

	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	if got := waits()[0]; got != 1*time.Minute {
		t.Fatalf("first wait = %v, want the 1-minute backoff fallback", got)
	}
}

// --- Run: network/5xx errors on register and poll's request stability -----

// TestRun_RegisterServerErrorUsesEscalatingBackoff checks a run of 5xx
// responses to POST /v1/register (protocol has no dedicated code for this;
// any 5xx is "network/5xx" for backoff purposes, issue #16) climbs the
// same 1 → 2 → 5 minute sequence 410 uses, since both share one backoff
// counter (register.backoff).
func TestRun_RegisterServerErrorUsesEscalatingBackoff(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)
	stub.RegisterStatus(http.StatusInternalServerError, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	// Let two failed attempts happen (so at least two backoff waits are
	// recorded: 1m then 2m), then let registration through.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(waits()) < 2 {
		time.Sleep(time.Millisecond)
	}
	stub.RegisterStatus(0, 0)

	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	got := waits()
	if len(got) < 2 || got[0] != 1*time.Minute || got[1] != 2*time.Minute {
		t.Fatalf("first two waits = %v, want [1m 2m]", got)
	}
}

// TestRun_PollKeepsSameRequestIDWhilePending checks that ordinary pending
// polls never rotate the requestId or pairing code — only an explicit
// resolution (410/expiry, rejection, approval) does (issue #16: "a poll
// transport error does not abandon the request until it expires" implies,
// a fortiori, that an outright successful "still pending" poll certainly
// does not).
func TestRun_PollKeepsSameRequestIDWhilePending(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, _ := newTestDeps(t, stub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	id := pendingRequestID(t, stub)
	for i := 0; i < 3; i++ {
		again := pendingRequestID(t, stub)
		if again != id {
			t.Fatalf("poll id changed from %q to %q while request was still pending", id, again)
		}
	}
	stub.Approve(id, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
}

// --- Run: expiresAt reached locally ---------------------------------------

// oneShotExpiryClock is a clock.Clock that normally reports a time safely
// before any expiresAt a test will construct, and reports a time safely
// after it exactly once per Arm call — self-clearing, so the very next
// registration's own local-expiry check (the first thing pollUntilResolved
// does for it, before it ever calls Poll) is not also fooled into
// expiring instantly. A plain Fake clock cannot do this: Run's busy-loop
// tests never really wait, so advancing a shared Fake far enough to trip
// one registration's TTL leaves it far enough ahead to trip every
// subsequent registration's TTL too, which starves the test of the very
// GET /v1/register/<id> calls it needs to see to progress (register.go
// checks local expiry before ever polling), which is what this type is
// designed to make impossible.
type oneShotExpiryClock struct {
	mu    sync.Mutex
	armed bool
}

func (c *oneShotExpiryClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.armed {
		c.armed = false
		return time.Now().Add(24 * time.Hour)
	}
	return time.Now().Add(-24 * time.Hour)
}

// Arm makes the next single Now() call report a time in the future, so
// pollUntilResolved's very next local-expiry check treats the current
// registration as expired.
func (c *oneShotExpiryClock) Arm() {
	c.mu.Lock()
	c.armed = true
	c.mu.Unlock()
}

// TestRun_LocalExpiryTreatsAsExpired checks that once this box's own clock
// judges a request past its expiresAt, Run treats it as expired (issue
// #16) even without an explicit 410 from mon-server — arming a one-shot
// "expired" reading right after the first request starts polling, and
// observing a fresh registration (new pairing code) follow.
func TestRun_LocalExpiryTreatsAsExpired(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, logBuf, _ := newTestDeps(t, stub)
	clk := &oneShotExpiryClock{}
	d.Clock = clk

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	firstID := pendingRequestID(t, stub)
	clk.Arm()

	seen := map[string]bool{firstID: true}
	secondID := waitForNewRequestID(t, stub, seen)
	stub.Approve(secondID, "ams-1", "tok")

	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	if strings.Count(logBuf.String(), "pairing code") < 2 {
		t.Fatalf("expected a second registration after local expiry, log: %q", logBuf.String())
	}
}

// --- Run: context cancellation --------------------------------------------

// TestRun_ContextCancelledReturnsPromptly checks Run returns quickly (not
// after any backoff/poll wait) once ctx is already done.
func TestRun_ContextCancelledReturnsPromptly(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, _ := newTestDeps(t, stub)
	// A real timer-based Sleep this time, so "promptly" is a meaningful
	// wall-clock assertion rather than something the recorder fakes away.
	d.Sleep = defaultSleep

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := Run(ctx, d)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Run took %v to return after cancellation, want well under 1s", elapsed)
	}
}

// TestRun_ContextCancelledDuringPollReturnsPromptly checks cancellation
// that arrives mid-flow (after the request was submitted and Run is
// sitting in the real pollAfter wait before its first poll) is noticed
// immediately rather than only once that wait elapses.
func TestRun_ContextCancelledDuringPollReturnsPromptly(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, _ := newTestDeps(t, stub)
	d.Sleep = defaultSleep

	ctx, cancel := context.WithCancel(context.Background())
	resCh := make(chan error, 1)
	go func() {
		_, err := Run(ctx, d)
		resCh <- err
	}()

	waitForRegisterPost(t, stub)
	start := time.Now()
	cancel()

	select {
	case err := <-resCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Run took %v to return after cancellation", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// --- PublicIPFromDial -----------------------------------------------------

// TestPublicIPFromDial_DialsAndReturnsLocalAddr checks the helper reaches
// a real listener and reports a non-empty local address.
func TestPublicIPFromDial_DialsAndReturnsLocalAddr(t *testing.T) {
	stub := servertest.NewStub(t)
	f := PublicIPFromDial(stub.URL())
	ip := f(context.Background())
	if ip == "" {
		t.Fatal("expected a non-empty local address dialing the stub")
	}
}

// TestPublicIPFromDial_BadURLReturnsEmpty checks the best-effort contract:
// an unreachable/malformed target yields "" rather than an error the
// caller would have to handle.
func TestPublicIPFromDial_BadURLReturnsEmpty(t *testing.T) {
	f := PublicIPFromDial("https://203.0.113.1:1") // TEST-NET-3, reserved
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := f(ctx); got != "" {
		t.Fatalf("got %q, want empty on dial failure", got)
	}
}

// TestPublicIPFromDial_NilOnEmptyDeps checks Deps.publicIP's own nil guard
// (not PublicIPFromDial itself, which is always non-nil once constructed).
func TestPublicIPFromDial_NilOnEmptyDeps(t *testing.T) {
	d := Deps{}
	if got := d.publicIP(context.Background()); got != "" {
		t.Fatalf("got %q, want empty from a nil PublicIP", got)
	}
}

// --- Run: the backoff ladders reset ---------------------------------------

// waitForBackoffWaits blocks until at least n non-pollAfter waits have been
// recorded and returns them, so a test can pin a ladder's steps without
// racing the goroutine Run is on.
func waitForBackoffWaits(t *testing.T, waits func() []time.Duration, n int) []time.Duration {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := filterBackoffWaits(waits()); len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d backoff waits; got %v", n, filterBackoffWaits(waits()))
	return nil
}

// wantWaits checks the recorded ladder steps begin with want.
func wantWaits(t *testing.T, waits func() []time.Duration, want ...time.Duration) {
	t.Helper()
	got := waitForBackoffWaits(t, waits, len(want))
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("backoff step %d = %v, want %v (all: %v)", i, got[i], w, got)
		}
	}
}

// TestRun_AcceptedRequestResetsBackoff pins the transient ladder's reset: a
// streak of failed POST /v1/register climbs 1 → 2 min, but once a request
// is accepted (202) the link is proven, so the next transport failure —
// here a 5xx on the poll — starts again at one minute instead of
// inheriting the 5-minute step the streak was heading for (spec §3.2's
// ladder is per failure streak, not per Run call).
func TestRun_AcceptedRequestResetsBackoff(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)
	stub.FailNextRegisters(2, http.StatusInternalServerError)
	stub.FailNextPolls(1, http.StatusInternalServerError)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	// Two failed registrations (1 min, 2 min), then a 202 that resets the
	// ladder, then one failed poll — which must wait 1 min, not 5.
	wantWaits(t, waits, 1*time.Minute, 2*time.Minute, 1*time.Minute)

	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "tok")
	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after approval")
	}
}

// TestRun_RejectedResetsBackoff pins the other reset: after a rejection the
// box waits its fixed hour (spec §3.2) and then files a wholly new request
// — a fresh attempt at being adopted, so the first failure of that attempt
// waits one minute, not the step the pre-rejection failures had climbed to.
func TestRun_RejectedResetsBackoff(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, _, waits := newTestDeps(t, stub)
	// Two failed polls climb the transient ladder to its second step; the
	// third poll sees whatever state the request is in by then.
	stub.FailNextPolls(2, http.StatusInternalServerError)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	firstID := pendingRequestID(t, stub)
	// Armed before the rejection, which is what sets the rest in motion:
	// the registration that follows the hour-long wait fails once.
	stub.FailNextRegisters(1, http.StatusInternalServerError)
	stub.Reject(firstID)

	wantWaits(t, waits, 1*time.Minute, 2*time.Minute, rejectedWait, 1*time.Minute)

	secondID := waitForNewRequestID(t, stub, map[string]bool{firstID: true})
	stub.Approve(secondID, "ams-1", "tok2")
	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the second approval")
	}
}

// TestRun_FailedRegisterLogsWarnPerAttempt checks spec §7's operator view:
// a POST /v1/register that fails must say so once per attempt, with the
// error and the wait, so `docker logs` explains why no pairing code has
// appeared.
func TestRun_FailedRegisterLogsWarnPerAttempt(t *testing.T) {
	stub := servertest.NewStub(t)
	d, _, logBuf, waits := newTestDeps(t, stub)
	stub.FailNextRegisters(2, http.StatusInternalServerError)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resCh := make(chan *state.File, 1)
	go func() {
		f, err := Run(ctx, d)
		if err != nil {
			t.Errorf("Run: %v", err)
			return
		}
		resCh <- f
	}()

	wantWaits(t, waits, 1*time.Minute, 2*time.Minute)
	id := pendingRequestID(t, stub)
	stub.Approve(id, "ams-1", "tok")
	select {
	case <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after approval")
	}

	lines := regexp.MustCompile(`registration request failed: [^\n]*retrying in ([0-9a-z]+)`).FindAllStringSubmatch(logBuf.String(), -1)
	if len(lines) != 2 {
		t.Fatalf("expected one warn line per failed attempt, got %d: %q", len(lines), logBuf.String())
	}
	if lines[0][1] != "1m0s" || lines[1][1] != "2m0s" {
		t.Fatalf("logged waits = %q, %q, want 1m0s, 2m0s", lines[0][1], lines[1][1])
	}
}
