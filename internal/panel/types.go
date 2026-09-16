// Package panel is mon-server's client for the panel monitoring contract v1 —
// the `/mon/v1/*` endpoints the panel opens for mon-server (panel contract,
// spec mon-server.md §4). mon-server is the only caller: the panel never calls
// out, so this package is the whole conversation with it.
//
// The package is deliberately transport only. It marshals the contract's wire
// shapes, authenticates, retries what the contract says may be retried and
// classifies every failure into a sentinel the caller can branch on. It holds
// no state beyond the last observed contract header: the once-a-minute poll
// loop, the PANEL_DOWN counter of §4.1 and the events outbox sit on top of it
// and own all persistence.
package panel

// Contract is the contract version this client implements. It appears in the
// `X-Mon-Contract` response header of every successful answer and in the
// `contract` field of GET /state (contract §1). An incompatible change moves
// the panel to /mon/v2/; compatible additions (new optional fields, new
// reasons, new event kinds) keep version 1, so unknown fields in a response
// are ignored rather than rejected.
const Contract = 1

// HeaderContract is the response header carrying the contract version.
const HeaderContract = "X-Mon-Contract"

// ContentTypeJSON is the content type of every request and response body
// (contract §3).
const ContentTypeJSON = "application/json; charset=utf-8"

// Inbound kinds. An AWG server is addressed as kind awg with inboundId 0 so
// that xray and AWG targets share the key (monClientId, kind, inboundId, path)
// (contract §3).
const (
	InboundKindXray = "xray"
	InboundKindAWG  = "awg"
)

// Paths a target is probed over (contract §3): direct is the real server's own
// address, proxy is the address the host override points at.
const (
	PathDirect = "direct"
	PathProxy  = "proxy"
)

// Event kinds (contract §4.6).
const (
	// EventKindTarget carries monClientId, inboundKind, inboundId and path.
	EventKindTarget = "target"
	// EventKindMonClient carries monClientId and nothing about a target.
	EventKindMonClient = "mon_client"
	// EventKindPanel carries neither, and is always notified: mon-server has
	// already sent it to Telegram itself, the panel only files it.
	EventKindPanel = "panel"
)

// Target states, the from/to values of a target event (contract §4.6,
// spec §7.2).
const (
	TargetUp       = "UP"
	TargetDown     = "DOWN"
	TargetFlapping = "FLAPPING"
	TargetUnknown  = "UNKNOWN"
	TargetPaused   = "PAUSED"
)

// mon-client states. ONLINE and OFFLINE are the from/to values of a mon_client
// event; NEVER is mon-server's own state for a mon-client that has not sent a
// first heartbeat (spec §3) and reaches the panel only in the registry
// snapshot of POST /probe/ensure.
const (
	MonClientOnline  = "ONLINE"
	MonClientOffline = "OFFLINE"
	MonClientNever   = "NEVER"
)

// Panel states, the from/to values of a panel event (contract §4.6).
const (
	PanelUp   = "PANEL_UP"
	PanelDown = "PANEL_DOWN"
)

// The reason dictionary (contract §4.6, spec §7.2 and §4.1). The panel accepts
// a reason outside this list and shows it as it came, so the dictionary is a
// convenience for mon-server, not a validation rule.
const (
	ReasonTCPRefused        = "tcp_refused"
	ReasonTCPTimeout        = "tcp_timeout"
	ReasonTLSTimeout        = "tls_timeout"
	ReasonRealityRealCert   = "reality_real_cert"
	ReasonAWGNoHandshake    = "awg_no_handshake"
	ReasonHTTPError         = "http_error"
	ReasonHeartbeatMissed   = "heartbeat_missed"
	ReasonRecovered         = "recovered"
	ReasonFlapping          = "flapping"
	ReasonConfigDisabled    = "config_disabled"
	ReasonConfigEnabled     = "config_enabled"
	ReasonMonClientOffline  = "mon_client_offline"
	ReasonMonClientDisabled = "mon_client_disabled"
	// Reasons of a panel event (spec §4.1): why the panel was declared down.
	ReasonHTTPTimeout = "http_timeout"
	ReasonHTTP5xx     = "http_5xx"
	ReasonConnRefused = "conn_refused"
)

// Error codes the panel returns in the body of a failed request
// (contract §3, §4.3, §4.4).
const (
	CodeInvalidBody      = "invalid_body"
	CodeOverrideDisabled = "override_disabled"
	CodeProbeNotEnsured  = "probe_not_ensured"
	CodeXrayUnavailable  = "xray_unavailable"
	CodeBatchTooLarge    = "batch_too_large"
	// CodeUnknownInbound appears per item in the ignored list of a 200, not as
	// a request failure: the panel keeps nothing for a deleted inbound.
	CodeUnknownInbound = "unknown_inbound"
)

// Batch limits of contract §3. The client enforces them before sending so the
// panel never has to answer 413 batch_too_large.
const (
	MaxEvents     = 1000
	MaxStats      = 2000
	MaxMonClients = 200
	MaxBodyBytes  = 1 << 20 // 1 MiB
)

// State is the answer to GET /state (contract §4.1): the panel's sanitised
// configuration snapshot plus the revision mon-server compares against the
// last one it saw.
type State struct {
	Contract     int        `json:"contract"`
	PanelVersion string     `json:"panelVersion"`
	ServerTime   int64      `json:"serverTime"`
	Revision     string     `json:"revision"`
	Override     Override   `json:"override"`
	Probe        ProbeState `json:"probe"`
	Inbounds     []Inbound  `json:"inbounds"`
	Stale        Stale      `json:"stale"`
}

// Override is the panel's host override (contract §4.1). Host is the empty
// string when Enabled is false.
type Override struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
}

// ProbeState describes the probe set. SubID is a pointer because the contract
// distinguishes "never created" (null, the first POST /probe/ensure creates it)
// from any string value.
type ProbeState struct {
	SubID       *string `json:"subId"`
	LastEnsured int64   `json:"lastEnsured"`
}

// Ensured reports whether the probe set has ever been created. It is false
// exactly when the panel sent subId: null.
func (p ProbeState) Ensured() bool { return p.SubID != nil }

// SubIDValue returns the subId, or the empty string when the probe set has
// never been created. Use Ensured to tell the two apart.
func (p ProbeState) SubIDValue() string {
	if p.SubID == nil {
		return ""
	}
	return *p.SubID
}

// Inbound is one entry of the sanitised inbound list of GET /state: every
// client xray inbound including the disabled ones, plus the AWG server when it
// exists. Port is the public port. Nothing about keys or stream settings is
// carried.
type Inbound struct {
	Kind      string `json:"kind"`
	InboundID int64  `json:"inboundId"`
	Tag       string `json:"tag"`
	Remark    string `json:"remark"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Enable    bool   `json:"enable"`
}

// Stale carries the panel's own STALE threshold, the number of minutes of
// silence after which the panel considers mon-server stale (contract §2).
type Stale struct {
	ThresholdMinutes int `json:"thresholdMinutes"`
}

// MonClientSnapshot is one mon-client in the registry snapshot posted with
// every POST /probe/ensure. The snapshot is a full replacement, not a patch,
// and the panel keeps it only as a cache for its UI (contract §4.3).
type MonClientSnapshot struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Region        string `json:"region"`
	State         string `json:"state"`
	LastHeartbeat int64  `json:"lastHeartbeat"`
}

// ProbeEnsureRequest is the body of POST /probe/ensure.
type ProbeEnsureRequest struct {
	MonClients []MonClientSnapshot `json:"monClients"`
}

// ProbeEnsureResult is the answer to POST /probe/ensure. Created lists what
// this call had to create, usually nothing; Present is the size of the probe
// set afterwards.
type ProbeEnsureResult struct {
	SubID       string     `json:"subId"`
	Revision    string     `json:"revision"`
	LastEnsured int64      `json:"lastEnsured"`
	Created     []ProbeRef `json:"created"`
	Present     int        `json:"present"`
}

// ProbeRef names one probe account by the inbound it belongs to.
type ProbeRef struct {
	Kind      string `json:"kind"`
	InboundID int64  `json:"inboundId"`
}

// ProbeConfigs is the answer to GET /probe/configs: the probe set's material
// for one path. Revision lets mon-server drop the answer when the panel's
// configuration has already moved on (contract §4.4).
type ProbeConfigs struct {
	Revision string       `json:"revision"`
	Path     string       `json:"path"`
	Items    []ConfigItem `json:"items"`
}

// ConfigItem is one probe target as the panel renders it: a subscription link
// for an xray inbound, or a named AmneziaWG configuration for the AWG server.
// Disabled inbounds are absent from the list, which is how mon-server sees
// PAUSED.
type ConfigItem struct {
	Kind      string `json:"kind"`
	InboundID int64  `json:"inboundId"`
	Link      string `json:"link,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Conf      string `json:"conf,omitempty"`
}

// Event is one state transition sent to POST /events (contract §4.6).
//
// The fields a kind does not carry must be absent from the wire, not present
// and zero: a panel event carries no monClientId and nothing about a target.
// InboundID is a pointer for the same reason, because the AWG server's real
// inboundId is 0 and omitempty would drop it. Send events through the client,
// which applies Normalized to every one of them.
type Event struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Kind        string `json:"kind"`
	MonClientID string `json:"monClientId,omitempty"`
	InboundKind string `json:"inboundKind,omitempty"`
	InboundID   *int64 `json:"inboundId,omitempty"`
	Path        string `json:"path,omitempty"`
	From        string `json:"from"`
	To          string `json:"to"`
	Reason      string `json:"reason"`
	Notified    bool   `json:"notified"`
}

// Normalized returns e with the fields its kind does not carry cleared, so
// that a struct reused or half-filled upstream still goes on the wire in the
// shape contract §4.6 requires. A panel event is always notified: mon-server
// sends those to Telegram itself and the panel only files them.
func (e Event) Normalized() Event {
	switch e.Kind {
	case EventKindTarget:
		return e
	case EventKindMonClient:
		e.InboundKind = ""
		e.InboundID = nil
		e.Path = ""
		return e
	case EventKindPanel:
		e.MonClientID = ""
		e.InboundKind = ""
		e.InboundID = nil
		e.Path = ""
		e.Notified = true
		return e
	default:
		return e
	}
}

// EventsRequest is the body of POST /events.
type EventsRequest struct {
	Events []Event `json:"events"`
}

// EventsResult is the answer to POST /events. A duplicate id is not an error,
// and an event about an inbound the panel no longer knows is reported in
// Ignored with a 200 (contract §3).
type EventsResult struct {
	Accepted   int            `json:"accepted"`
	Duplicates int            `json:"duplicates"`
	Ignored    []IgnoredEvent `json:"ignored"`
}

// IgnoredEvent names one event the panel skipped and why.
type IgnoredEvent struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// Stat is one five-minute aggregate sent to POST /stats (contract §4.7). The
// key is (MonClientID, InboundKind, InboundID, Path, BucketStart) and the panel
// upserts on it, so resending a bucket is safe.
//
// The latency fields are pointers because the contract requires null, not 0,
// when there is nothing to report: all of them are null when NOk is 0, and
// HandshakeMS is null for everything but AWG.
type Stat struct {
	MonClientID  string `json:"monClientId"`
	InboundKind  string `json:"inboundKind"`
	InboundID    int64  `json:"inboundId"`
	Path         string `json:"path"`
	BucketStart  int64  `json:"bucketStart"`
	NOk          int    `json:"nOk"`
	NFail        int    `json:"nFail"`
	LatencyMinMS *int64 `json:"latencyMinMs"`
	LatencyAvgMS *int64 `json:"latencyAvgMs"`
	LatencyMaxMS *int64 `json:"latencyMaxMs"`
	HandshakeMS  *int64 `json:"handshakeMs"`
}

// StatsRequest is the body of POST /stats.
type StatsRequest struct {
	Stats []Stat `json:"stats"`
}

// StatsResult is the answer to POST /stats. Ignored holds the aggregates the
// panel skipped, an unknown inbound being the usual cause; the contract fixes
// only that it is a list.
type StatsResult struct {
	Accepted int           `json:"accepted"`
	Ignored  []IgnoredStat `json:"ignored"`
}

// IgnoredStat identifies one skipped aggregate. Every field is optional: the
// contract pins the shape of the events ignore list but only the emptiness of
// this one, so the client decodes whatever key the panel echoes back.
type IgnoredStat struct {
	MonClientID string `json:"monClientId,omitempty"`
	InboundKind string `json:"inboundKind,omitempty"`
	InboundID   *int64 `json:"inboundId,omitempty"`
	Path        string `json:"path,omitempty"`
	BucketStart int64  `json:"bucketStart,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Int64Ptr returns a pointer to v, for the nullable millisecond fields of Stat
// and for Event.InboundID.
func Int64Ptr(v int64) *int64 { return &v }

// StringPtr returns a pointer to v, for ProbeState.SubID.
func StringPtr(v string) *string { return &v }
