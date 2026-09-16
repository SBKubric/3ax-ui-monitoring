package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Transport defaults of contract §3 and spec mon-server.md §4.
const (
	// DefaultTimeout is the per-request timeout. Every attempt, including each
	// retry, gets its own; the caller's context still caps the whole sequence.
	DefaultTimeout = 10 * time.Second
	// MaxRetries is how many times a retryable failure is retried, once per
	// entry in the 1 s → 2 s → 4 s backoff sequence.
	MaxRetries = 3
	// maxResponseBytes bounds what the client will read from the panel, so a
	// runaway response cannot exhaust mon-server's memory.
	maxResponseBytes = 8 << 20
	// maxErrorBodyBytes bounds the error envelope read for logging.
	maxErrorBodyBytes = 64 << 10
	// retryHeadroom is the time a retry must still have after its backoff wait
	// before it is worth making: a retry that cannot finish a round trip
	// inside the caller's budget is skipped rather than overrunning the cycle.
	retryHeadroom = 500 * time.Millisecond
)

// backoffDelays is the wait before each retry (contract §3): 1 s, 2 s, 4 s.
// Seven seconds of waiting plus four ten-second attempts stays inside the
// one-minute poll cycle even in the worst case.
var backoffDelays = [MaxRetries]time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// Sentinel failures. Every method returns an error that matches exactly one of
// the first five through errors.Is, or ErrUnavailable for anything that left
// mon-server without an answer.
var (
	// ErrNotFound is a bare 404: no token, a wrong token, a wrong path, or
	// monitoring switched off on the panel (contract §2). The panel is up and
	// answering, so this must not count towards PANEL_DOWN; spec §8 has
	// mon-server alert the owner over Telegram itself instead.
	ErrNotFound = errors.New("panel: 404, wrong token, wrong path or monitoring disabled")

	// ErrOverrideDisabled is 409 override_disabled from GET /probe/configs
	// without a host: there is no proxy path to render configs for.
	ErrOverrideDisabled = errors.New("panel: host override is disabled")

	// ErrProbeNotEnsured is 409 probe_not_ensured from GET /probe/configs: the
	// probe set does not exist yet and POST /probe/ensure must run first.
	ErrProbeNotEnsured = errors.New("panel: probe set is not ensured")

	// ErrXrayUnavailable is 503 xray_unavailable from POST /probe/ensure: the
	// probe set is partly created and the next cycle finishes it (spec §4
	// step 2). The panel answered, so this is not a panel outage and it is not
	// retried inside the cycle.
	ErrXrayUnavailable = errors.New("panel: xray is unavailable, probe set is incomplete")

	// ErrBatchTooLarge is a batch over the limits of contract §3, whether the
	// client refused it before sending or the panel answered 413.
	ErrBatchTooLarge = errors.New("panel: batch is too large")

	// ErrRejected matches every 4xx: the request was wrong and repeating it
	// will not help, so it is logged and dropped, a batch as a whole. A bare
	// 404 matches ErrRejected as well as ErrNotFound; test for ErrNotFound
	// first.
	ErrRejected = errors.New("panel: request rejected")

	// ErrUnavailable matches the failures that left mon-server without an
	// answer after the retries: a network error, a timeout, or a 5xx other
	// than 503 xray_unavailable. These are the failures that advance the
	// PANEL_DOWN counter of spec §4.1; FailureReason gives the reason code for
	// the panel event.
	ErrUnavailable = errors.New("panel: unavailable")

	// ErrInvalidOptions reports a Client that cannot be built from the given
	// Options.
	ErrInvalidOptions = errors.New("panel: invalid options")
)

// APIError is the panel's error envelope (contract §3): a stable snake_case
// code plus a message meant for logs. A bare 404 has no body, so Code and
// Message are empty for it.
type APIError struct {
	Op      string
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

// Error implements error.
func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("panel: %s: %d %s: %s", e.Op, e.Status, e.Code, e.Message)
	case e.Code != "":
		return fmt.Sprintf("panel: %s: %d %s", e.Op, e.Status, e.Code)
	default:
		return fmt.Sprintf("panel: %s: %d %s", e.Op, e.Status, http.StatusText(e.Status))
	}
}

// Is maps the status and code onto the package sentinels so that callers can
// branch with errors.Is instead of comparing numbers.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrOverrideDisabled:
		return e.Status == http.StatusConflict && e.Code == CodeOverrideDisabled
	case ErrProbeNotEnsured:
		return e.Status == http.StatusConflict && e.Code == CodeProbeNotEnsured
	case ErrXrayUnavailable:
		return e.Status == http.StatusServiceUnavailable && e.Code == CodeXrayUnavailable
	case ErrBatchTooLarge:
		return e.Status == http.StatusRequestEntityTooLarge || e.Code == CodeBatchTooLarge
	case ErrRejected:
		return e.Status >= 400 && e.Status < 500
	}
	return false
}

// TransportError is a request that produced no usable answer: the network
// failed, the request timed out, or the panel answered 5xx. It matches
// ErrUnavailable and carries the reason code for the PANEL_DOWN event of
// spec §4.1 along with how many attempts were spent.
type TransportError struct {
	Op       string
	Status   int // 0 when no response arrived
	Reason   string
	Attempts int
	Err      error
}

// Error implements error.
func (e *TransportError) Error() string {
	attempts := "attempt"
	if e.Attempts != 1 {
		attempts = "attempts"
	}
	return fmt.Sprintf("panel: %s: %s after %d %s: %v", e.Op, e.Reason, e.Attempts, attempts, e.Err)
}

// Unwrap exposes the underlying cause, which is an *APIError for a 5xx and the
// network or context error otherwise.
func (e *TransportError) Unwrap() error { return e.Err }

// Is reports every transport failure as ErrUnavailable.
func (e *TransportError) Is(target error) bool { return target == ErrUnavailable }

// FailureReason returns the reason code to put on the panel event of spec §4.1
// — http_timeout, http_5xx or conn_refused — for an error that counts towards
// PANEL_DOWN, and the empty string for anything else.
func FailureReason(err error) string {
	var te *TransportError
	if errors.As(err, &te) {
		return te.Reason
	}
	return ""
}

// ContractHeader records what the X-Mon-Contract header of the last successful
// response said (contract §1).
type ContractHeader struct {
	// Value is the raw header, empty when the response did not carry one.
	Value string
	// Present is whether the header was there at all.
	Present bool
	// OK is whether it announced the contract version this client implements.
	OK bool
}

// Options configures a Client. Only BaseURL and Token are required.
type Options struct {
	// BaseURL is the panel's base URL including its webBasePath, for example
	// https://panel.example.net:2053/xyz/. Endpoints are joined onto it as
	// <base>/mon/v1/<endpoint>, with or without a trailing slash.
	BaseURL string
	// Token is the panel's monToken, sent as Authorization: Bearer.
	Token string
	// HTTPClient is the transport. Nil means a client with DefaultTimeout and
	// the default transport.
	HTTPClient *http.Client
	// Clock is the time source used to measure the retry budget against the
	// caller's context deadline. Nil means clock.System.
	Clock clock.Clock
	// Log receives one warning per dropped or failed request. Nil discards.
	Log *slog.Logger
	// Timeout is the per-request timeout. Zero means DefaultTimeout (10 s).
	Timeout time.Duration
	// Backoff waits before retry number attempt (1-based) or returns an error
	// to abandon the sequence. Nil means DefaultBackoff, the 1 s → 2 s → 4 s
	// sequence of contract §3; tests replace it to avoid waiting.
	Backoff func(ctx context.Context, attempt int) error
}

// Client talks to one panel over the monitoring contract. It is safe for
// concurrent use and holds no state beyond the last contract header seen.
type Client struct {
	base    *url.URL
	token   string
	http    *http.Client
	clock   clock.Clock
	log     *slog.Logger
	timeout time.Duration
	backoff func(ctx context.Context, attempt int) error

	mu       sync.Mutex
	contract ContractHeader
}

// New builds a Client. It fails when the base URL is missing, unparseable or
// not absolute http(s), and when the token is empty.
func New(opts Options) (*Client, error) {
	if opts.BaseURL == "" {
		return nil, fmt.Errorf("%w: base url is empty", ErrInvalidOptions)
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: base url %q: %w", ErrInvalidOptions, opts.BaseURL, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("%w: base url %q is not http or https", ErrInvalidOptions, opts.BaseURL)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("%w: base url %q has no host", ErrInvalidOptions, opts.BaseURL)
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("%w: token is empty", ErrInvalidOptions)
	}

	base = base.JoinPath("mon", "v1")
	base.RawQuery = ""
	base.Fragment = ""

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	c := &Client{
		base:    base,
		token:   opts.Token,
		http:    httpClient,
		clock:   opts.Clock,
		log:     opts.Log,
		timeout: timeout,
		backoff: opts.Backoff,
	}
	if c.clock == nil {
		c.clock = clock.System{}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.backoff == nil {
		c.backoff = DefaultBackoff
	}
	return c, nil
}

// BaseURL returns the joined base, <panel base>/mon/v1, that every endpoint
// hangs off.
func (c *Client) BaseURL() string { return c.base.String() }

// Timeout is the per-request timeout, which is also the least a caller's
// budget has to be for a request to stand a chance.
func (c *Client) Timeout() time.Duration { return c.timeout }

// LastContract reports the X-Mon-Contract header of the most recent successful
// response. A mismatch is logged as a warning and never fails a request: the
// contract says compatible changes keep the version, so the header is a signal
// for the operator, not a gate.
func (c *Client) LastContract() ContractHeader {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.contract
}

// State fetches the panel's configuration snapshot (contract §4.1). A bare 404
// here is the "wrong token or monitoring disabled" case of spec §4.
func (c *Client) State(ctx context.Context) (State, error) {
	var out State
	err := c.do(ctx, http.MethodGet, "state", nil, nil, &out)
	return out, err
}

// ProbeEnsure makes sure the probe set exists and hands the panel the full
// registry snapshot, which replaces the panel's cache wholesale
// (contract §4.3). A nil snapshot is sent as an empty list, not as null.
func (c *Client) ProbeEnsure(ctx context.Context, snapshot []MonClientSnapshot) (ProbeEnsureResult, error) {
	var out ProbeEnsureResult
	if len(snapshot) > MaxMonClients {
		return out, fmt.Errorf("%w: %d mon-clients, limit is %d", ErrBatchTooLarge, len(snapshot), MaxMonClients)
	}
	if snapshot == nil {
		snapshot = []MonClientSnapshot{}
	}
	err := c.do(ctx, http.MethodPost, "probe/ensure", nil, ProbeEnsureRequest{MonClients: snapshot}, &out)
	return out, err
}

// ProbeConfigs fetches the probe set's material for one path (contract §4.4).
// An empty host asks for the subscription as users get it, with the host
// override applied, which is the proxy path and needs the override enabled; a
// non-empty host asks for the same material addressed at that host, which is
// the direct path.
func (c *Client) ProbeConfigs(ctx context.Context, host string) (ProbeConfigs, error) {
	var query url.Values
	if host != "" {
		query = url.Values{"host": []string{host}}
	}
	var out ProbeConfigs
	err := c.do(ctx, http.MethodGet, "probe/configs", query, nil, &out)
	return out, err
}

// DeleteProbe removes the probe set from the panel (contract §4.5). It is the
// decommissioning call: mon-server runs it on uninstall.
func (c *Client) DeleteProbe(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "probe", nil, nil, nil)
}

// SendEvents posts a batch of transitions (contract §4.6). Every event is
// normalised to the shape its kind requires before it goes out. An empty batch
// is a no-op and makes no request. The whole batch is accepted or dropped
// together: the panel validates it before writing anything, so a 4xx here
// means the batch must be logged and dropped, not resent.
func (c *Client) SendEvents(ctx context.Context, events []Event) (EventsResult, error) {
	var out EventsResult
	if len(events) == 0 {
		return out, nil
	}
	if len(events) > MaxEvents {
		return out, fmt.Errorf("%w: %d events, limit is %d", ErrBatchTooLarge, len(events), MaxEvents)
	}
	body := EventsRequest{Events: make([]Event, len(events))}
	for i, e := range events {
		body.Events[i] = e.Normalized()
	}
	err := c.do(ctx, http.MethodPost, "events", nil, body, &out)
	return out, err
}

// SendStats posts a batch of five-minute aggregates (contract §4.7). The panel
// upserts on the bucket key, so resending is safe. An empty batch is a no-op.
func (c *Client) SendStats(ctx context.Context, stats []Stat) (StatsResult, error) {
	var out StatsResult
	if len(stats) == 0 {
		return out, nil
	}
	if len(stats) > MaxStats {
		return out, fmt.Errorf("%w: %d stats, limit is %d", ErrBatchTooLarge, len(stats), MaxStats)
	}
	err := c.do(ctx, http.MethodPost, "stats", nil, StatsRequest{Stats: stats}, &out)
	return out, err
}

// DefaultBackoff waits out the delay before retry number attempt (1-based),
// returning early with the context's error if the caller gives up first.
func DefaultBackoff(ctx context.Context, attempt int) error {
	d := BackoffDelay(attempt)
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

// BackoffDelay returns the wait before retry number attempt (1-based): 1 s,
// 2 s, then 4 s, which is also what any further attempt would wait.
func BackoffDelay(attempt int) time.Duration {
	if attempt < 1 {
		return 0
	}
	if attempt > MaxRetries {
		attempt = MaxRetries
	}
	return backoffDelays[attempt-1]
}

// do runs one endpoint call, retrying what contract §3 allows to be retried.
func (c *Client) do(ctx context.Context, method, endpoint string, query url.Values, body, out any) error {
	op := method + " " + endpoint

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("panel: %s: encode body: %w", op, err)
		}
		if len(payload) > MaxBodyBytes {
			return fmt.Errorf("%w: %s body is %d bytes, limit is %d", ErrBatchTooLarge, op, len(payload), MaxBodyBytes)
		}
	}

	u := c.base.JoinPath(endpoint)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	target := u.String()

	var last error
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			delay := BackoffDelay(attempt)
			if !c.budgetAllows(ctx, delay) {
				c.log.Warn("panel request gave up, retry budget spent",
					"op", op, "attempt", attempt, "error", last)
				return annotate(last, attempt)
			}
			if err := c.backoff(ctx, attempt); err != nil {
				// Giving up during the wait is mon-server's own doing when the
				// caller cancelled; a spent deadline still belongs to the
				// failure that made the retry necessary.
				if errors.Is(err, context.Canceled) {
					return fmt.Errorf("panel: %s: %w", op, err)
				}
				return annotate(last, attempt)
			}
		}

		err := c.attempt(ctx, method, target, payload, op, out)
		if err == nil {
			return nil
		}
		last = err
		if !isRetryable(err) {
			c.log.Warn("panel request failed, not retrying",
				"op", op, "error", err)
			return annotate(err, attempt+1)
		}
		if attempt >= MaxRetries {
			c.log.Warn("panel request failed, retries exhausted",
				"op", op, "attempts", attempt+1, "error", err)
			return annotate(err, attempt+1)
		}
	}
}

// attempt performs one HTTP round trip and turns its outcome into a typed
// error or a decoded response.
func (c *Client) attempt(ctx context.Context, method, target string, payload []byte, op string, out any) error {
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, target, reader)
	if err != nil {
		return fmt.Errorf("panel: %s: build request: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", ContentTypeJSON)
		req.ContentLength = int64(len(payload))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// A caller that cancelled is mon-server shutting down, not the panel
		// failing: it must not count towards PANEL_DOWN.
		if ctxErr := ctx.Err(); errors.Is(ctxErr, context.Canceled) {
			return fmt.Errorf("panel: %s: %w", op, ctxErr)
		}
		return &TransportError{Op: op, Reason: networkReason(err), Err: err}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.recordContract(op, resp.Header)
		if out == nil || resp.StatusCode == http.StatusNoContent {
			return nil
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
			// A malformed body is the panel misbehaving, not a wrong request;
			// treat it like a 5xx so the next attempt can do better.
			return &TransportError{
				Op:     op,
				Status: resp.StatusCode,
				Reason: ReasonHTTPError,
				Err:    fmt.Errorf("decode response: %w", err),
			}
		}
		return nil
	}

	apiErr := readAPIError(op, resp)
	if retryableStatus(apiErr) {
		return &TransportError{Op: op, Status: apiErr.Status, Reason: ReasonHTTP5xx, Err: apiErr}
	}
	return apiErr
}

// budgetAllows reports whether the caller's deadline still leaves room for a
// wait of delay plus a round trip. The poll cycle passes its one minute in as
// a context deadline, and the retry sequence must not outlast it.
func (c *Client) budgetAllows(ctx context.Context, delay time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return deadline.Sub(c.clock.Now()) > delay+retryHeadroom
}

// recordContract stores the X-Mon-Contract header and warns once per response
// on a mismatch.
func (c *Client) recordContract(op string, header http.Header) {
	value := header.Get(HeaderContract)
	seen := ContractHeader{
		Value:   value,
		Present: value != "",
		OK:      value == strconv.Itoa(Contract),
	}
	c.mu.Lock()
	c.contract = seen
	c.mu.Unlock()
	if !seen.OK {
		c.log.Warn("panel contract header mismatch",
			"op", op, "expected", Contract, "got", value)
	}
}

// readAPIError decodes the panel's error envelope, tolerating a bare 404 and
// any other body that is not the envelope.
func readAPIError(op string, resp *http.Response) *APIError {
	out := &APIError{Op: op, Status: resp.StatusCode}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		return out
	}
	var envelope struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		out.Message = string(bytes.TrimSpace(body))
		return out
	}
	out.Code = envelope.Error
	out.Message = envelope.Message
	return out
}

// retryableStatus reports whether a failed response deserves another attempt:
// 5xx does, except 503 xray_unavailable, which is the panel telling mon-server
// that the probe set is incomplete and the next cycle should finish it.
func retryableStatus(e *APIError) bool {
	if e.Status < 500 {
		return false
	}
	if e.Status == http.StatusServiceUnavailable && e.Code == CodeXrayUnavailable {
		return false
	}
	return true
}

// isRetryable reports whether err is worth another attempt. Only transport
// failures are: contract §3 has 4xx logged and dropped.
func isRetryable(err error) bool {
	var te *TransportError
	if !errors.As(err, &te) {
		return false
	}
	// A cancelled parent context is mon-server shutting down or the cycle
	// running out, not something a retry can fix.
	return !errors.Is(err, context.Canceled)
}

// annotate records how many attempts a transport failure cost, for the log and
// for the caller's PANEL_DOWN bookkeeping.
func annotate(err error, attempts int) error {
	var te *TransportError
	if errors.As(err, &te) && te.Attempts == 0 {
		te.Attempts = attempts
	}
	return err
}

// networkReason classifies a failure that never reached a status code into the
// reason dictionary of spec §4.1.
func networkReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ReasonHTTPTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonHTTPTimeout
	}
	return ReasonConnRefused
}
