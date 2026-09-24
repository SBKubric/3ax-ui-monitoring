package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

const (
	// contractPath is the version-carrying prefix every contract route
	// lives under (contract §1: "<webBasePath>mon/v1/"). An incompatible
	// change becomes /mon/v2/ and a different client, which is why the
	// version is a constant here and not a parameter.
	contractPath = "/mon/v1"

	// contractHeader and contractVersion are the handshake the panel puts
	// on every successful answer (contract §1). A different value means the
	// panel is speaking a version this client was not written against;
	// compatible changes never bump it, so mismatch is a warning, not a
	// refusal.
	contractHeader  = "X-Mon-Contract"
	contractVersion = "1"

	// requestTimeout bounds one attempt end to end (spec §4: "таймаут 10
	// с"). It bounds a single HTTP round trip, nothing more: a poll cycle
	// calls several endpoints, each retrying independently up to maxRetries
	// times, so a panel that is 5xx-ing or hanging on every endpoint can
	// still stretch a whole cycle to a few minutes — comfortably past "the
	// next tick" a shorter-scoped reading of this comment used to promise.
	// What is actually guaranteed: no single request hangs past this, and
	// Poller's pollCycleDeadline bounds the cycle as a whole so it can never
	// run unbounded even so.
	requestTimeout = 10 * time.Second

	// maxResponseBytes caps what this client will read from the panel. The
	// panel's own request limit is 1 MiB (contract §3); its answers —
	// /probe/configs with an item per inbound — are the largest thing it
	// sends, and 4 MiB is far above any believable inbound count while
	// still bounding memory if the far end is not, in fact, the panel.
	maxResponseBytes = 4 << 20

	// maxRetries is how many times a failed request is repeated before the
	// caller sees the failure (spec §4: delays 1 → 2 → 4 s, "не дольше
	// минуты цикла" — four attempts and seven seconds of waiting fit
	// comfortably inside one 60 s cycle).
	maxRetries = 3
)

// retryDelays are the waits before retry 1, 2 and 3 (spec §4: "1 → 2 → 4
// с"). Indexed by attempt number, so len(retryDelays) == maxRetries is an
// invariant the retry loop depends on.
var retryDelays = [maxRetries]time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

// ErrNotFound is the bare 404 the panel returns to anyone without a valid
// monToken, and to everyone when monitoring is switched off (contract §2:
// the panel does not reveal that it is there). mon-server treats it as
// "wrong token, wrong path, or monitoring disabled" — a configuration
// problem to alert an operator about (spec §8), not a panel outage, so it
// deliberately does not count toward PANEL_DOWN.
var ErrNotFound = errors.New("panel: 404")

// ErrBadBody is a 200 whose body will not decode as the contract's JSON
// (PLAUSIBLE finding). It is deliberately not a netError: spec §4 retries
// only network failures, 5xx and timeouts, and a captive portal or a
// misconfigured reverse proxy answering its own HTML page on 200 is none of
// those — retrying it three times would just fetch three more copies of the
// same wrong page, and mapping it to conn_refused (as wrapping it in
// netError used to) tells the operator the wrong story. errors.Is(err,
// ErrBadBody) is true on the returned error; errors.As still reaches the
// underlying *json.SyntaxError or *json.UnmarshalTypeError for logs.
var ErrBadBody = errors.New("panel: response body is not valid contract JSON")

// APIError is any answer the panel gave with its error body (contract §3:
// {"error": "...", "message": "..."}). Code is the stable snake_case code to
// branch on — xray_unavailable, override_disabled, probe_not_ensured — and
// Message is free-form text for logs only.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error renders the status, code and message in one line for logs.
func (e *APIError) Error() string {
	return fmt.Sprintf("panel: %d %s: %s", e.Status, e.Code, e.Message)
}

// Retryable reports whether repeating the request could plausibly help. Only
// 5xx qualifies (spec §4: "ретраи только на сеть/5xx/таймаут"): a 4xx is the
// panel telling us the request itself is wrong, and sending it again would
// produce the same answer while the caller drops the batch.
func (e *APIError) Retryable() bool { return e.Status >= 500 }

// netError is a request that never produced an HTTP response at all —
// connection refused, DNS failure, TLS failure, or the 10 s timeout firing.
// It is a distinct type from APIError because the two map to different
// PANEL_DOWN reasons (spec §4.1: conn_refused vs http_timeout) and because
// every netError is retryable while only some APIErrors are.
type netError struct {
	op  string
	err error
}

func (e *netError) Error() string { return fmt.Sprintf("panel: %s: %v", e.op, e.err) }
func (e *netError) Unwrap() error { return e.err }

// Timeout reports whether this failure was the request running out of time
// rather than failing outright, matching net.Error's own contract so that
// errors.As to net.Error keeps working through the wrapper.
func (e *netError) Timeout() bool {
	if errors.Is(e.err, context.DeadlineExceeded) {
		return true
	}
	var ne interface{ Timeout() bool }
	return errors.As(e.err, &ne) && ne.Timeout()
}

// IsRetryable reports whether err is the kind of failure the client already
// retried and gave up on — a transport failure or a 5xx. Callers that own a
// batch (step 7's stats flush) use it to tell "the panel is unreachable,
// keep the rows" from "the panel rejected this, drop it". ErrBadBody is
// neither *netError nor *APIError, so it is correctly never retryable here:
// spec §4 does not list a bad body among the retryable causes.
func IsRetryable(err error) bool {
	var ne *netError
	if errors.As(err, &ne) {
		return true
	}
	var ae *APIError
	return errors.As(err, &ae) && ae.Retryable()
}

// Client is everything mon-server asks of the panel (contract §4). It is an
// interface rather than a bare *HTTPClient so the poller, the config builder
// (step 5) and the stats flush (step 7) can be driven from paneltest.Stub —
// and so that a nil-panel install can be represented by simply not having
// one.
type Client interface {
	// State fetches the panel's configuration snapshot and revision
	// (contract §4.1). A bare 404 here is ErrNotFound.
	State(ctx context.Context) (*State, error)
	// ProbeEnsure guarantees the probe account set exists and replaces the
	// panel's cached mon-client registry with snapshot (contract §4.3).
	ProbeEnsure(ctx context.Context, snapshot []MonClientSnapshot) (*EnsureResult, error)
	// ProbeConfigs fetches the probe material for one path (contract §4.4).
	// host == "" asks for the proxy path, with the panel's host override
	// applied; a non-empty host asks for the direct path against that
	// address.
	ProbeConfigs(ctx context.Context, host string) (*ProbeConfigs, error)
	// PostEvents delivers one batch of state transitions (contract §4.6).
	PostEvents(ctx context.Context, events []store.EventPayload) (*EventsResult, error)
	// PostStats delivers one batch of 5-minute aggregates (contract §4.7).
	PostStats(ctx context.Context, stats []StatPayload) (*StatsResult, error)
}

// Sleeper is how the client waits between retries. It exists so tests can
// assert the 1 → 2 → 4 s schedule without spending seven seconds observing
// it; production uses sleep, which is the same wait bounded by the context.
type Sleeper func(ctx context.Context, d time.Duration) error

// Option customises an HTTPClient at construction. The set is deliberately
// small: everything an operator configures lives in settings (§9.4), so
// options exist only for what a test needs to control.
type Option func(*HTTPClient)

// WithSleeper replaces the retry wait. A test passes one that records the
// delay and returns immediately.
func WithSleeper(s Sleeper) Option {
	return func(c *HTTPClient) { c.sleep = s }
}

// WithTimeout replaces the 10 s per-attempt timeout (spec §4). Only tests
// should use it — to make a slow panel produce a real timeout in
// milliseconds instead of seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *HTTPClient) { c.hc.Timeout = d }
}

// WithHTTPClient replaces the whole http.Client, for a caller that needs its
// own transport. (A custom TLS root for a panel with a private certificate
// is WithRootCAs.)
// The timeout is applied to the client that is passed in, so a caller does
// not have to remember spec §4's 10 s itself.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *HTTPClient) {
		hc.Timeout = c.hc.Timeout
		c.hc = hc
	}
}

// HTTPClient is the real contract client: one http.Client, one bearer token,
// and the retry policy spec §4 fixes. It is safe for concurrent use, though
// in practice only the poller goroutine uses it.
type HTTPClient struct {
	base  string // panel base URL + /mon/v1, no trailing slash
	token string
	clk   clock.Clock
	hc    *http.Client
	sleep Sleeper

	warnContract sync.Once
}

// Compile-time proof that the real client satisfies the interface every
// other package depends on.
var _ Client = (*HTTPClient)(nil)

// NewHTTPClient builds a client for the panel at baseURL — the panel's base
// including its webBasePath, exactly as an operator types it into the
// settings page (§9.4: "base URL панели с webBasePath") — with monToken as
// the bearer. The contract path is appended here, so a trailing slash on
// baseURL is normalised away rather than producing a double slash the
// panel's router would not match.
func NewHTTPClient(baseURL, token string, clk clock.Clock, opts ...Option) *HTTPClient {
	c := &HTTPClient{
		base:  strings.TrimRight(baseURL, "/") + contractPath,
		token: token,
		clk:   clk,
		hc:    &http.Client{Timeout: requestTimeout},
		sleep: sleep,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// sleep is the production Sleeper: a plain wait that gives up early if the
// context is cancelled, so a shutdown during a retry backoff does not have
// to wait out the remaining four seconds.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// State implements Client.
func (c *HTTPClient) State(ctx context.Context) (*State, error) {
	var out State
	if err := c.do(ctx, http.MethodGet, "/state", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProbeEnsure implements Client. A nil snapshot is sent as an empty array
// rather than JSON null: the body is a full replacement of the panel's cache
// (contract §4.3), and "mon-server currently knows of no mon-clients" is a
// legitimate thing to say.
func (c *HTTPClient) ProbeEnsure(ctx context.Context, snapshot []MonClientSnapshot) (*EnsureResult, error) {
	if snapshot == nil {
		snapshot = []MonClientSnapshot{}
	}
	body := struct {
		MonClients []MonClientSnapshot `json:"monClients"`
	}{MonClients: snapshot}

	var out EnsureResult
	if err := c.do(ctx, http.MethodPost, "/probe/ensure", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProbeConfigs implements Client. The empty host is sent as no query
// parameter at all, not as host=, because the panel distinguishes the two
// paths by the parameter's presence (contract §4.4).
func (c *HTTPClient) ProbeConfigs(ctx context.Context, host string) (*ProbeConfigs, error) {
	var q url.Values
	if host != "" {
		q = url.Values{"host": []string{host}}
	}

	var out ProbeConfigs
	if err := c.do(ctx, http.MethodGet, "/probe/configs", q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostEvents implements Client. It sends whatever it is given: enforcing the
// 1000-event limit (contract §3) is the caller's job, because only the
// caller knows how to split its own queue.
func (c *HTTPClient) PostEvents(ctx context.Context, events []store.EventPayload) (*EventsResult, error) {
	if events == nil {
		events = []store.EventPayload{}
	}
	body := struct {
		Events []store.EventPayload `json:"events"`
	}{Events: events}

	var out EventsResult
	if err := c.do(ctx, http.MethodPost, "/events", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PostStats implements Client, under the same retry and batching rules as
// PostEvents.
func (c *HTTPClient) PostStats(ctx context.Context, stats []StatPayload) (*StatsResult, error) {
	if stats == nil {
		stats = []StatPayload{}
	}
	body := struct {
		Stats []StatPayload `json:"stats"`
	}{Stats: stats}

	var out StatsResult
	if err := c.do(ctx, http.MethodPost, "/stats", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// do performs one contract call with the retry policy of spec §4: the
// request body is marshalled once and replayed from memory on each attempt,
// so a retry sends exactly the same bytes; only a transport failure or a 5xx
// is repeated, and a 4xx returns immediately for the caller to drop.
func (c *HTTPClient) do(ctx context.Context, method, path string, query url.Values, reqBody, out any) error {
	var payload []byte
	if reqBody != nil {
		var err error
		payload, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("panel: marshal %s %s: %w", method, path, err)
		}
	}

	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	for attempt := 0; ; attempt++ {
		err := c.attempt(ctx, method, u, payload, out)
		if err == nil {
			return nil
		}
		// An untrusted certificate stays untrusted however often it is
		// asked: return at once (the Check button would otherwise sit
		// through the whole backoff), but as the retryable netError it is,
		// so a batch caller keeps its rows for when panelCa is fixed.
		if !IsRetryable(err) || IsUnknownAuthority(err) || attempt >= maxRetries {
			return err
		}
		delay := retryDelays[attempt]
		slog.Warn("panel: retrying",
			"method", method, "path", path, "attempt", attempt+1, "in", delay,
			"at", c.clk.Now(), "err", err)
		if serr := c.sleep(ctx, delay); serr != nil {
			// The wait was cut short by shutdown; report the request
			// failure that caused it, which is what the caller acts on.
			return err
		}
	}
}

// attempt is one HTTP round trip: build, send, classify. It never retries —
// that decision belongs to do, which is the only place that knows how many
// attempts have already been spent.
func (c *HTTPClient) attempt(ctx context.Context, method, u string, payload []byte, out any) error {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return fmt.Errorf("panel: build %s %s: %w", method, u, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return &netError{op: method + " " + u, err: err}
	}
	defer func() {
		// Drain a little before closing so the connection can go back to
		// the pool instead of being torn down after every call.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK:
		c.checkContract(resp)
		if out == nil {
			return nil
		}
		// A fresh zero value per attempt: a retry must not decode on top of
		// whatever an earlier, rejected attempt's body happened to fill in
		// before it failed partway through.
		resetZero(out)
		// Plain decoder, no DisallowUnknownFields: the contract (§1)
		// requires mon-server to ignore fields it does not know, so that
		// the panel can add optional ones without a version bump.
		dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
		if err := dec.Decode(out); err != nil {
			if _, ok := out.(emptyMeansAccepted); ok && errors.Is(err, io.EOF) {
				// A bare 200 with no body at all (Decode's plain io.EOF,
				// not ErrUnexpectedEOF) from a panel that predates
				// per-element answers: the batch went in whole
				// (decision #50). out stays the zero value — nothing
				// rejected.
				return nil
			}
			var syn *json.SyntaxError
			var ute *json.UnmarshalTypeError
			if errors.As(err, &syn) || errors.As(err, &ute) {
				// The panel answered 200 but what came back is not its
				// contract JSON (PLAUSIBLE finding) — most likely something
				// else entirely is listening at panelUrl. A body that starts
				// decoding correctly and then runs out mid-way (a genuine
				// I/O error, io.ErrUnexpectedEOF) is left as a netError
				// below: that is the connection failing, not the panel
				// answering something wrong.
				return fmt.Errorf("panel: %w: %w", ErrBadBody, err)
			}
			return &netError{op: "decode " + u, err: err}
		}
		return nil

	case resp.StatusCode == http.StatusNoContent:
		c.checkContract(resp)
		return nil

	case resp.StatusCode == http.StatusNotFound:
		// A 404 with the contract's error body is an unknown route on a
		// panel that did authenticate us; a bare one is the panel refusing
		// to admit the API exists at all (contract §2).
		if apiErr := readAPIError(resp); apiErr != nil {
			return apiErr
		}
		return ErrNotFound

	default:
		if apiErr := readAPIError(resp); apiErr != nil {
			return apiErr
		}
		return &APIError{
			Status:  resp.StatusCode,
			Code:    "unexpected_status",
			Message: fmt.Sprintf("%s answered %s with no contract error body", u, resp.Status),
		}
	}
}

// emptyMeansAccepted marks the answer types a panel from before per-element
// validation may send as a bare 200 with no body, which reads as "the whole
// batch accepted" (decision #50). Only POST /events and /stats have such an
// answer: an empty GET /state or /probe/configs is still a bad response,
// never a zero-value snapshot.
type emptyMeansAccepted interface{ emptyMeansAccepted() }

func (*EventsResult) emptyMeansAccepted() {}
func (*StatsResult) emptyMeansAccepted()  {}

// Rejections maps a batch answer's rejected list onto the batch that was
// sent: batch index → the rejection. n is the batch length; ids, when not
// nil, are the batch's event ids by index, and an entry whose id is in the
// batch is placed by id even if its index disagrees — the id is the stronger
// identity of the two. An entry that matches no element (index out of range
// and no known id) is logged and ignored, which leaves that element counted
// as accepted: a panel that cannot say what it refused has not refused it.
func Rejections(n int, rejected []Rejected, ids []string) map[int]Rejected {
	if len(rejected) == 0 {
		return nil
	}
	var byID map[string]int
	out := make(map[int]Rejected, len(rejected))
	for _, r := range rejected {
		idx := -1
		switch {
		case r.Id != "" && r.Index >= 0 && r.Index < len(ids) && ids[r.Index] == r.Id:
			idx = r.Index
		case r.Id != "" && ids != nil:
			if byID == nil {
				byID = make(map[string]int, len(ids))
				for i, id := range ids {
					byID[id] = i
				}
			}
			if i, ok := byID[r.Id]; ok {
				idx = i
			}
		case r.Index >= 0 && r.Index < n:
			idx = r.Index
		}
		if idx < 0 {
			slog.Warn("panel: rejection matches nothing in the batch", "index", r.Index, "id", r.Id, "error", r.Error, "batch", n)
			continue
		}
		out[idx] = r
	}
	return out
}

// checkContract warns once per client if the panel is announcing a contract
// version this build was not written against. It is a warning and not a
// failure because compatible changes never bump the version (contract §1):
// if it ever does change, mon-server should still keep monitoring while an
// operator upgrades it.
func (c *HTTPClient) checkContract(resp *http.Response) {
	got := resp.Header.Get(contractHeader)
	if got == contractVersion {
		return
	}
	c.warnContract.Do(func() {
		slog.Warn("panel: unexpected contract version",
			"header", contractHeader, "got", got, "want", contractVersion)
	})
}

// resetZero clears *out back to its zero value before decoding. Without it a
// retry that decodes on top of a struct an earlier, rejected attempt
// partially filled in could keep fields the new response never sent — out is
// always a pointer to a struct this client owns, so the reflection here is
// paid once per attempt, not per field.
func resetZero(out any) {
	v := reflect.ValueOf(out)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v.Elem().Set(reflect.Zero(v.Elem().Type()))
}

// readAPIError parses the contract's error body (§3) off a failed response,
// returning nil when the body is empty or is not that shape — which is how
// the bare 404 of contract §2 is told apart from an unknown route.
func readAPIError(resp *http.Response) *APIError {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Error == "" {
		return nil
	}
	return &APIError{Status: resp.StatusCode, Code: parsed.Error, Message: parsed.Message}
}
