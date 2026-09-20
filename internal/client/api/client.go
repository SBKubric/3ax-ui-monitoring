// Package api is mon-client's HTTP client to mon-server (mon-protocol.md,
// every route except the tunnel probe — that one goes through a
// per-target *http.Transport in internal/client/probe, since it must dial
// through a socks5 proxy or a netstack device rather than this package's
// plain client). It owns exactly one thing well: turning mon-server's
// {error, message} envelope and status codes into the Go errors the rest
// of mon-client branches on (architecture brief §1's error mapping table).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// maxBodyBytes bounds every response body this client reads (architecture
// brief §1: "Bodies ≤ 1 MiB"). mon-server's own handlers cap their bodies
// at the same size (internal/api/*.go); this is the mirror image — a
// mon-server that is compromised, buggy or just fronted by something odd
// must not be able to make mon-client allocate unbounded memory decoding a
// response.
const maxBodyBytes = 1 << 20

// Client is mon-client's handle on mon-server. HTTP is a caller-supplied
// *http.Client (never proxied — this package's own default is the plain
// no-proxy client every registration/config/heartbeat call uses)
// specifically so a caller can hand it one whose Transport trusts a test
// server's certificate (internal/client/servertest) or, in production, an
// *http.Client with no special configuration beyond the system's own root
// CAs (spec §2: "доверяет системным CA; пиннинга нет"). No per-Client
// timeout is set: every call takes ctx and honours whatever deadline the
// caller attaches to it, which is how the heartbeat call gets its own
// heartbeatMs budget (protocol §5.3) without this package needing to know
// about config-driven timeouts at all.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a Client for baseURL (spec §2: "https://<ip>:443"), using hc
// for every request. A nil hc gets http.DefaultClient's zero-value
// equivalent — an *http.Client with no special transport — which is enough
// for production (system CAs, no proxy); tests hand in one that trusts
// their own server instead.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{}
	}
	return &Client{BaseURL: baseURL, HTTP: hc}
}

// Register submits a registration request (protocol §2.1, POST
// /v1/register). It is never authenticated — a mon-client by definition
// has no token yet when it calls this.
func (c *Client) Register(ctx context.Context, req proto.RegisterRequest) (*proto.RegisterResponse, error) {
	var out proto.RegisterResponse
	if err := c.do(ctx, "register", http.MethodPost, "/v1/register", req, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Poll checks a registration request's status (protocol §2.2, GET
// /v1/register/<requestId>). Like Register, it carries no bearer token —
// the requestId itself is the secret.
func (c *Client) Poll(ctx context.Context, requestID string) (*proto.PollResponse, error) {
	var out proto.PollResponse
	path := "/v1/register/" + requestID
	if err := c.do(ctx, "poll", http.MethodGet, path, nil, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Config fetches the current config document (protocol §4.2, GET
// /v1/config), authenticated with the client token. A 503 config_not_ready
// comes back as *StatusError — the brief's own note is that the caller
// treats it as "empty config, retry next cycle" rather than this package
// inventing a sentinel for a condition that is, from mon-client's side,
// just an ordinary temporary failure.
func (c *Client) Config(ctx context.Context) (*proto.ConfigDoc, error) {
	var out proto.ConfigDoc
	if err := c.do(ctx, "config", http.MethodGet, "/v1/config", nil, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat sends one heartbeat (protocol §5.3, POST /v1/heartbeat),
// authenticated with the client token. The caller is expected to attach
// heartbeatMs as ctx's deadline (config's ProbeParams.HeartbeatTimeoutMs) —
// this package has no opinion on how long a heartbeat may take.
func (c *Client) Heartbeat(ctx context.Context, hb *proto.HeartbeatRequest) (*proto.HeartbeatResponse, error) {
	var out proto.HeartbeatResponse
	if err := c.do(ctx, "heartbeat", http.MethodPost, "/v1/heartbeat", hb, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// do is every method's body: encode (if body is non-nil), send, decode.
// authenticated adds the bearer header protocol §3 requires on every route
// but /v1/register*.
func (c *Client) do(ctx context.Context, op, method, path string, body any, authenticated bool, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("api: %s: encode request: %w", op, err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("api: %s: build request: %w", op, err)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &NetError{Op: op, Err: err}
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return &NetError{Op: op, Err: err}
	}
	if len(raw) > maxBodyBytes {
		return &StatusError{Status: resp.StatusCode, Code: "body_too_large", Message: "response body exceeded 1 MiB"}
	}

	if resp.StatusCode/100 != 2 {
		return statusToError(resp, raw)
	}

	if out != nil && len(raw) > 0 {
		// Unknown fields are tolerated on purpose (protocol §1: both sides
		// must accept fields they do not yet know) — no
		// DisallowUnknownFields.
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("api: %s: decode response: %w", op, err)
		}
	}
	return nil
}

// errorBody is mon-server's error envelope, identical on every /v1/* route
// (protocol §1, mirrored from the panel contract): {"error": "<snake
// code>", "message": "<human text>"}.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// statusToError implements architecture brief §1's mapping table: 401 →
// ErrTokenRevoked, 403 → ErrDisabled, 410 → ErrRequestExpired, 429 (with
// Retry-After) → *RateLimitError, everything else non-2xx → *StatusError.
// A body that fails to decode as errorBody still produces a StatusError —
// mon-server always sends the envelope, but a body-mangling proxy in front
// of it should not turn into a panic or a swallowed status code.
func statusToError(resp *http.Response, raw []byte) error {
	var eb errorBody
	_ = json.Unmarshal(raw, &eb)

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrTokenRevoked
	case http.StatusForbidden:
		return ErrDisabled
	case http.StatusGone:
		return ErrRequestExpired
	case http.StatusTooManyRequests:
		return &RateLimitError{RetryAfter: retryAfter(resp)}
	default:
		return &StatusError{Status: resp.StatusCode, Code: eb.Error, Message: eb.Message}
	}
}

// retryAfter parses the Retry-After header as whole seconds (protocol
// §2.1's rate limit uses only the seconds form, never the HTTP-date form,
// so that is the only one this parses); a missing or unparsable header
// yields zero, which the caller falls back to its own backoff for.
func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
