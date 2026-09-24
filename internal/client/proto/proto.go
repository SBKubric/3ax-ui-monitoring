// Package proto is the wire form of mon-protocol.md, mon-client's side of
// it: registration, config, tunnel probe and heartbeat. It intentionally
// duplicates the shape of mon-server's internal/registry (ConfigDoc etc.)
// and internal/state (HeartbeatRequest etc.) rather than importing them —
// architecture brief §1 forbids internal/client/** from importing any
// mon-server package, so the two sides of the protocol are kept in sync by
// discipline (and by the round-trip tests in this package) rather than by
// a shared Go type.
package proto

import (
	"fmt"
	"strconv"
	"strings"
)

// TargetKey names one (inbound, path) pair a mon-client probes (protocol
// §4.2, §5.2). It is comparable so it works as a map key — the config
// applier (step 8) needs set membership to drop results for targets that
// vanished from a new revision.
type TargetKey struct {
	InboundKind string `json:"inboundKind"`
	InboundID   int    `json:"inboundId"`
	Path        string `json:"path"`
}

// String renders the key in the `?target=` query form the tunnel probe
// uses (protocol §5.2, e.g. "xray:12:proxy").
func (k TargetKey) String() string {
	return fmt.Sprintf("%s:%d:%s", k.InboundKind, k.InboundID, k.Path)
}

// ParseTargetKey parses the `<kind>:<inboundId>:<path>` form String
// produces back into a TargetKey. It only checks shape (exactly three
// colon-separated parts, the middle one a non-negative integer) — mon-client
// never needs to validate a kind or path against the protocol's own
// enumeration, since every key it ever parses came from a config document
// mon-server already built.
func ParseTargetKey(s string) (TargetKey, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return TargetKey{}, fmt.Errorf("proto: malformed target key %q", s)
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || id < 0 {
		return TargetKey{}, fmt.Errorf("proto: malformed target key %q: bad inboundId", s)
	}
	return TargetKey{InboundKind: parts[0], InboundID: id, Path: parts[2]}, nil
}

// Target is one target of a config document (protocol §4.2). Link and Conf
// are the panel's material copied verbatim by mon-server; exactly one of
// them is set depending on Protocol, which is why both are omitempty.
type Target struct {
	TargetKey
	Protocol string `json:"protocol"`
	Link     string `json:"link,omitempty"`
	Conf     string `json:"conf,omitempty"`
}

// ProbeParams are the probe cycle's timings (protocol §4.2), taken from the
// config document as-is — mon-client does not choose or default any of
// these itself, it only ever uses whatever the document last carried.
type ProbeParams struct {
	IntervalMs         int64 `json:"intervalMs"`
	BudgetMs           int64 `json:"budgetMs"`
	ConnectMs          int64 `json:"connectMs"`
	TlsMs              int64 `json:"tlsMs"`
	HeadersMs          int64 `json:"headersMs"`
	StartJitterMs      int64 `json:"startJitterMs"`
	HeartbeatTimeoutMs int64 `json:"heartbeatTimeoutMs"`
}

// ConfigDoc is the GET /v1/config document (protocol §4.2). Field names and
// order mirror mon-server's internal/registry.ConfigDoc exactly, since both
// are just views of the same bytes on the wire.
type ConfigDoc struct {
	ConfigRevision string      `json:"configRevision"`
	MonClientID    string      `json:"monClientId"`
	ProbeURL       string      `json:"probeUrl"`
	Probe          ProbeParams `json:"probe"`
	Targets        []Target    `json:"targets"`
}

// RegisterRequest is the POST /v1/register body (protocol §2.1).
type RegisterRequest struct {
	PairingCode string `json:"pairingCode"`
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	PublicIP    string `json:"publicIp"`
}

// RegisterResponse is the 202 body (protocol §2.1). RequestID is a secret:
// whoever holds it can poll the request's status and, once approved, is
// paired with mon-server as this box.
type RegisterResponse struct {
	RequestID   string `json:"requestId"`
	PollAfterMs int64  `json:"pollAfter"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// PollResponse is the GET /v1/register/<requestId> body (protocol §2.2).
// MonClientID and Token are only present once Status is "approved" —
// omitempty on decode simply leaves them at their zero value otherwise,
// which is exactly "not approved yet".
type PollResponse struct {
	Status      string `json:"status"`
	MonClientID string `json:"monClientId,omitempty"`
	Token       string `json:"token,omitempty"`
}

// Result is one target's probe outcome inside a cycle (protocol §5.3).
// Nullable numbers and strings are pointers so "not measured" (nil) stays
// distinguishable from a measured zero — connectMs of 0 for a loopback xray
// dial is a real, meaningful value, not an absent one.
type Result struct {
	TargetKey
	Ok          bool    `json:"ok"`
	ConnectMs   *int64  `json:"connectMs"`
	TlsMs       *int64  `json:"tlsMs"`
	TtfbMs      *int64  `json:"ttfbMs"`
	HandshakeMs *int64  `json:"handshakeMs"`
	EgressIp    *string `json:"egressIp"`
	Reason      *string `json:"reason"`
	Detail      *string `json:"detail"`
}

// Cycle is one probe round buffered for heartbeat delivery (protocol §5.1,
// §5.3, §6). Unverified marks a cycle whose heartbeat was never
// acknowledged: it is resent for statistics only, since a live state
// transition may never be replayed after the fact (protocol §5.3).
type Cycle struct {
	Seq        int64    `json:"seq"`
	Ts         int64    `json:"ts"`
	Unverified bool     `json:"unverified"`
	Results    []Result `json:"results"`
}

// ClientInfo is mon-client's self-report on every heartbeat (protocol
// §5.3). ConfigError is a pointer because null ("my config is fine") and ""
// are different states a mon-client may need to send, and the distinction
// has to survive encoding.
//
// ConfigError is about the revision as a whole (it did not apply, or the
// xray child is down); RejectedTargets is about single targets of a
// revision that did apply (decision #53 п. 3). Absent or empty means every
// target of the applied revision is being probed.
type ClientInfo struct {
	Version         string           `json:"version"`
	XrayVersion     string           `json:"xrayVersion"`
	UptimeMs        int64            `json:"uptimeMs"`
	ConfigError     *string          `json:"configError"`
	RejectedTargets []RejectedTarget `json:"rejectedTargets,omitempty"`
}

// RejectedTarget is one target of the applied revision mon-client could
// not turn into a probe (protocol §5.3 client.rejectedTargets): its link or
// .conf did not parse, or its AWG device refused the config. Target is the
// TargetKey in its String form ("awg:3:direct"); Error is the first line
// of the reason, at most 256 characters.
type RejectedTarget struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// HeartbeatRequest is the POST /v1/heartbeat body (protocol §5.3).
type HeartbeatRequest struct {
	MonClientID    string     `json:"monClientId"`
	ConfigRevision string     `json:"configRevision"`
	Client         ClientInfo `json:"client"`
	Cycles         []Cycle    `json:"cycles"`
}

// HeartbeatResponse is the 200 body (protocol §5.3): the revision
// mon-client should be converged on, mon-server's own receive time, and the
// highest cycle seq it has taken responsibility for.
type HeartbeatResponse struct {
	ConfigRevision string `json:"configRevision"`
	ServerTs       int64  `json:"serverTs"`
	AckSeq         int64  `json:"ackSeq"`
}

// ProbeEcho is the GET /v1/probe response body (protocol §5.2): mon-server
// echoes the nonce it was sent, its own view of the caller's egress
// address, and its receive time.
type ProbeEcho struct {
	Nonce    string `json:"nonce"`
	EgressIp string `json:"egressIp"`
	ServerTs int64  `json:"serverTs"`
}

// Reason dictionary (protocol §5.3, spec §5) — every failed Result carries
// one of these. They are the same strings the panel contract's diagnosis
// dictionary defines; mon-client is the only place that ever assigns one.
const (
	ReasonTCPRefused      = "tcp_refused"
	ReasonTCPTimeout      = "tcp_timeout"
	ReasonTLSTimeout      = "tls_timeout"
	ReasonRealityRealCert = "reality_real_cert"
	ReasonAWGNoHandshake  = "awg_no_handshake"
	ReasonHTTPError       = "http_error"
	ReasonProbeTimeout    = "probe_timeout"
)
