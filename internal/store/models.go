package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

// Probe paths (spec mon-server.md §5, protocol §4.2): the route a mon-client
// takes to a target. "proxy" goes through the proxy front, "direct" straight
// to the real server.
const (
	PathProxy  = "proxy"
	PathDirect = "direct"
)

// Inbound kinds (panel contract §1): xray inbounds are addressed by the
// panel's numeric inbound id, the single AWG server by inbound id 0.
const (
	InboundKindXray = "xray"
	InboundKindAWG  = "awg"
)

// Target states (spec §7.2).
const (
	TargetUnknown  = "UNKNOWN"
	TargetUp       = "UP"
	TargetDown     = "DOWN"
	TargetFlapping = "FLAPPING"
	TargetPaused   = "PAUSED"
)

// mon-client states (spec §3, §7.3). NEVER is an approved mon-client that has
// not sent its first heartbeat yet.
const (
	ClientStateNever   = "NEVER"
	ClientStateOnline  = "ONLINE"
	ClientStateOffline = "OFFLINE"
)

// Registration request statuses (spec §6).
const (
	RequestPending  = "pending"
	RequestApproved = "approved"
	RequestRejected = "rejected"
	RequestExpired  = "expired"
)

// Panel reachability as cached in PanelState (spec §4.1).
const (
	PanelStatusUnknown = "UNKNOWN"
	PanelStatusUp      = "PANEL_UP"
	PanelStatusDown    = "PANEL_DOWN"
)

// MonClientIDPattern is the shape of a mon-client id: the slug of its name,
// at most 64 characters (spec §3, §6).
var MonClientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ValidMonClientID reports whether id may be used as a mon-client id.
func ValidMonClientID(id string) bool { return MonClientIDPattern.MatchString(id) }

// ValidPath reports whether p is one of the two probe paths.
func ValidPath(p string) bool { return p == PathProxy || p == PathDirect }

// DefaultPaths returns the paths a mon-client gets when the administrator does
// not narrow them down (spec §5).
func DefaultPaths() []string { return []string{PathProxy, PathDirect} }

// EncodePaths renders paths as the JSON array stored in MonClient.Paths.
func EncodePaths(paths []string) (string, error) {
	if paths == nil {
		paths = []string{}
	}
	b, err := json.Marshal(paths)
	if err != nil {
		return "", fmt.Errorf("encode paths: %w", err)
	}
	return string(b), nil
}

// DecodePaths parses MonClient.Paths. An empty column yields the default set,
// so a row written before paths were chosen still probes both routes.
func DecodePaths(raw string) ([]string, error) {
	if raw == "" {
		return DefaultPaths(), nil
	}
	var paths []string
	if err := json.Unmarshal([]byte(raw), &paths); err != nil {
		return nil, fmt.Errorf("decode paths %q: %w", raw, err)
	}
	return paths, nil
}

// NewEventID returns a UUID v7, the primary key form of events_outbox: it
// sorts by creation time, so ordering the outbox by id matches ordering it by
// ts (spec §3).
func NewEventID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("new event id: %w", err)
	}
	return id.String(), nil
}

// HashToken returns the hex SHA-256 of a client token, the only form of the
// token mon-server keeps (spec §6).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Models is every table mon-server migrates, in dependency order. Open runs
// AutoMigrate over exactly this list.
func Models() []any {
	return []any{
		&Setting{},
		&Admin{},
		&AdminSession{},
		&LoginAttempt{},
		&RegistrationRequest{},
		&MonClient{},
		&Target{},
		&PanelInbound{},
		&ClientConfig{},
		&EventOutbox{},
		&StatsBucket{},
		&ProbeSeen{},
	}
}

// Setting is one row of the key/value settings table (spec §3, §9.4). Use the
// typed Settings and PanelState accessors rather than reading rows directly.
type Setting struct {
	Key   string `gorm:"column:key;primaryKey;size:128"`
	Value string `gorm:"column:value;not null;default:''"`
}

// TableName pins the table name.
func (Setting) TableName() string { return "settings" }

// Admin is the single administrator row (spec §3, §9.1). It is written by
// `mon-server admin set <user>`; the password is only ever stored as a bcrypt
// hash.
type Admin struct {
	// ID is always AdminRowID: mon-server has exactly one administrator.
	ID           int64  `gorm:"column:id;primaryKey;autoIncrement:false"`
	Username     string `gorm:"column:username;size:64;not null"`
	PasswordHash string `gorm:"column:password_hash;not null"`
	// UpdatedAt is ms UTC, taken from the store's clock.
	UpdatedAt int64 `gorm:"column:updated_at;not null;autoUpdateTime:false"`
}

// TableName pins the table name.
func (Admin) TableName() string { return "admin" }

// AdminSession is a cookie session of the admin UI (spec §9.1): 24 hours from
// creation, dropped by the retention job once expired.
type AdminSession struct {
	// ID is the cookie value, 32 random bytes in base64url.
	ID string `gorm:"column:id;primaryKey;size:64"`
	// CreatedAt and ExpiresAt are ms UTC.
	CreatedAt int64  `gorm:"column:created_at;not null;autoCreateTime:false"`
	ExpiresAt int64  `gorm:"column:expires_at;not null;index:idx_ms_admin_sessions_expires_at"`
	IP        string `gorm:"column:ip;size:64;not null"`
}

// TableName pins the table name.
func (AdminSession) TableName() string { return "admin_sessions" }

// LoginAttempt counts failed admin logins per source IP: five failures lock
// the IP out for fifteen minutes (spec §9.1).
type LoginAttempt struct {
	IP       string `gorm:"column:ip;primaryKey;size:64"`
	Failures int    `gorm:"column:failures;not null"`
	// LockedUntil is ms UTC, 0 when the IP is not locked out.
	LockedUntil int64 `gorm:"column:locked_until;not null;index:idx_ms_login_attempts_locked_until"`
}

// TableName pins the table name.
func (LoginAttempt) TableName() string { return "login_attempts" }

// RegistrationRequest is a mon-client asking to join (spec §6). It lives five
// minutes; approving it issues a client token whose plaintext waits in
// ApprovedToken until the mon-client polls for it once.
type RegistrationRequest struct {
	// RequestID is 128 random bits in base64url.
	RequestID string `gorm:"column:request_id;primaryKey;size:64"`
	// PairingCode is the [A-Z2-9]{6} code the administrator checks against
	// the mon-client's log.
	PairingCode string `gorm:"column:pairing_code;size:16;not null"`
	Hostname    string `gorm:"column:hostname;size:255;not null"`
	Version     string `gorm:"column:version;size:64;not null"`
	// PublicIP is what the mon-client reports, RemoteIP what the request came
	// from; they differ behind NAT.
	PublicIP string `gorm:"column:public_ip;size:64;not null"`
	RemoteIP string `gorm:"column:remote_ip;size:64;not null;index:idx_ms_registration_requests_remote_ip"`
	// Status is one of RequestPending, RequestApproved, RequestRejected,
	// RequestExpired.
	Status string `gorm:"column:status;size:16;not null;index:idx_ms_registration_requests_status"`
	// CreatedAt and ExpiresAt are ms UTC.
	CreatedAt int64 `gorm:"column:created_at;not null;autoCreateTime:false"`
	ExpiresAt int64 `gorm:"column:expires_at;not null;index:idx_ms_registration_requests_expires_at"`
	// ApprovedToken is the one-shot plaintext client token. It is cleared as
	// soon as the mon-client collects it.
	ApprovedToken string `gorm:"column:approved_token;not null;default:''"`
	// MonClientID is filled on approval, including the replacement case where
	// it names an existing mon-client.
	MonClientID string `gorm:"column:mon_client_id;size:64;not null;default:''"`
}

// TableName pins the table name.
func (RegistrationRequest) TableName() string { return "registration_requests" }

// MonClient is a registered probing box (spec §3, §6).
type MonClient struct {
	// ID is the slug of the name, at most 64 of [A-Za-z0-9_.-]. It never
	// changes, not even when the box is replaced.
	ID     string `gorm:"column:id;primaryKey;size:64"`
	Name   string `gorm:"column:name;size:128;not null"`
	Region string `gorm:"column:region;size:64;not null"`
	// Paths is the JSON array of probe paths, e.g. ["proxy","direct"]. Use
	// DecodePaths and EncodePaths.
	Paths string `gorm:"column:paths;not null;default:''"`
	// TokenHash is the hex SHA-256 of the client token (HashToken); empty
	// once the token is revoked.
	TokenHash string `gorm:"column:token_hash;size:64;not null;default:'';index:idx_ms_mon_clients_token_hash"`
	Enabled   bool   `gorm:"column:enabled;not null;default:true"`
	// State is ClientStateOnline, ClientStateOffline or ClientStateNever.
	State string `gorm:"column:state;size:16;not null;index:idx_ms_mon_clients_state"`
	// LastHeartbeat is ms UTC of the last accepted heartbeat, 0 when none.
	LastHeartbeat int64  `gorm:"column:last_heartbeat;not null;default:0"`
	Version       string `gorm:"column:version;size:64;not null;default:''"`
	XrayVersion   string `gorm:"column:xray_version;size:64;not null;default:''"`
	// AppliedRevision is the config revision the mon-client reports running.
	AppliedRevision string `gorm:"column:applied_revision;size:64;not null;default:''"`
	// ConfigError is the last error the mon-client reported applying its
	// config, with ConfigErrorAt in ms UTC.
	ConfigError   string `gorm:"column:config_error;not null;default:''"`
	ConfigErrorAt int64  `gorm:"column:config_error_at;not null;default:0"`
	RemoteIP      string `gorm:"column:remote_ip;size:64;not null;default:''"`
	// ApprovedAt is ms UTC of the approval that created this row.
	ApprovedAt int64 `gorm:"column:approved_at;not null;default:0"`
	// MissedHeartbeats counts consecutive missed heartbeats (spec §7.3).
	MissedHeartbeats int `gorm:"column:missed_heartbeats;not null;default:0"`
}

// TableName pins the table name.
func (MonClient) TableName() string { return "mon_clients" }

// Target is one (mon-client, inbound, path) triple and its state machine
// bookkeeping (spec §7.2).
type Target struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	MonClientID string `gorm:"column:mon_client_id;size:64;not null;uniqueIndex:idx_ms_targets_identity,priority:1;index:idx_ms_targets_mon_client"`
	// InboundKind is InboundKindXray or InboundKindAWG.
	InboundKind string `gorm:"column:inbound_kind;size:16;not null;uniqueIndex:idx_ms_targets_identity,priority:2"`
	InboundID   int64  `gorm:"column:inbound_id;not null;uniqueIndex:idx_ms_targets_identity,priority:3"`
	// Path is PathProxy or PathDirect.
	Path string `gorm:"column:path;size:16;not null;uniqueIndex:idx_ms_targets_identity,priority:4"`
	// State is TargetUnknown, TargetUp, TargetDown, TargetFlapping or
	// TargetPaused; Since is ms UTC of entering it.
	State  string `gorm:"column:state;size:16;not null;index:idx_ms_targets_state"`
	Since  int64  `gorm:"column:since;not null;default:0"`
	Reason string `gorm:"column:reason;size:64;not null;default:''"`
	// ConsecutiveFail and ConsecutiveOK drive the downAfter/upAfter
	// thresholds.
	ConsecutiveFail int `gorm:"column:consecutive_fail;not null;default:0"`
	ConsecutiveOK   int `gorm:"column:consecutive_ok;not null;default:0"`
	// Transitions is the JSON array of recent UP<->DOWN transition times in
	// ms UTC, the window flapping detection looks at.
	Transitions string `gorm:"column:transitions;not null;default:''"`
	// FlappingUntil is ms UTC, 0 when the target is not held in FLAPPING.
	FlappingUntil int64 `gorm:"column:flapping_until;not null;default:0"`
	// LastResultAt is ms UTC of the last probe result applied.
	LastResultAt int64 `gorm:"column:last_result_at;not null;default:0"`
}

// TableName pins the table name.
func (Target) TableName() string { return "targets" }

// PanelInbound mirrors one inbound from the panel's last GET /state (§4).
type PanelInbound struct {
	InboundKind string `gorm:"column:inbound_kind;size:16;primaryKey"`
	InboundID   int64  `gorm:"column:inbound_id;primaryKey"`
	Protocol    string `gorm:"column:protocol;size:32;not null;default:''"`
	Port        int    `gorm:"column:port;not null;default:0"`
	Remark      string `gorm:"column:remark;size:255;not null;default:''"`
	Enable      bool   `gorm:"column:enable;not null;default:true"`
	// SeenRevision is the panel revision this row was last seen in; rows with
	// an older revision have disappeared from the panel.
	SeenRevision string `gorm:"column:seen_revision;size:64;not null;default:''"`
}

// TableName pins the table name.
func (PanelInbound) TableName() string { return "panel_inbounds" }

// ClientConfig is the assembled configuration document served to one
// mon-client by GET /v1/config (spec §5).
type ClientConfig struct {
	MonClientID string `gorm:"column:mon_client_id;primaryKey;size:64"`
	// Revision is the config revision: the first 16 hex of the SHA-256 of the
	// canonical document.
	Revision string `gorm:"column:revision;size:64;not null"`
	// Document is the JSON document itself.
	Document string `gorm:"column:document;not null"`
	// BuiltAt is ms UTC.
	BuiltAt int64 `gorm:"column:built_at;not null;default:0"`
}

// TableName pins the table name.
func (ClientConfig) TableName() string { return "client_configs" }

// EventOutbox is one contract event waiting for the panel (spec §3, §4 step 4).
// While the panel is down the outbox is also the 24-hour buffer.
type EventOutbox struct {
	// ID is a UUID v7, so that ordering by id matches ordering by time.
	ID string `gorm:"column:id;primaryKey;size:36"`
	// TS is the event time in ms UTC.
	TS int64 `gorm:"column:ts;not null;index:idx_ms_events_outbox_ts"`
	// Payload is the JSON of the contract event (contract §4.6).
	Payload string `gorm:"column:payload;not null"`
	// Notified records whether mon-server already told Telegram itself, which
	// it does while the panel is unreachable (spec §4.1).
	Notified bool `gorm:"column:notified;not null;default:false"`
	// SentAt is ms UTC of the panel accepting the event, NULL until then.
	SentAt *int64 `gorm:"column:sent_at;index:idx_ms_events_outbox_sent_at"`
}

// TableName pins the table name.
func (EventOutbox) TableName() string { return "events_outbox" }

// StatsBucket is one five-minute aggregate per target (spec §7.4). Latency
// columns are NULL when NOk is 0.
type StatsBucket struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	MonClientID string `gorm:"column:mon_client_id;size:64;not null;uniqueIndex:idx_ms_stats_buckets_identity,priority:1"`
	InboundKind string `gorm:"column:inbound_kind;size:16;not null;uniqueIndex:idx_ms_stats_buckets_identity,priority:2"`
	InboundID   int64  `gorm:"column:inbound_id;not null;uniqueIndex:idx_ms_stats_buckets_identity,priority:3"`
	Path        string `gorm:"column:path;size:16;not null;uniqueIndex:idx_ms_stats_buckets_identity,priority:4"`
	// BucketStart is ms UTC, a multiple of 300000.
	BucketStart int64 `gorm:"column:bucket_start;not null;uniqueIndex:idx_ms_stats_buckets_identity,priority:5"`
	NOk         int   `gorm:"column:n_ok;not null;default:0"`
	NFail       int   `gorm:"column:n_fail;not null;default:0"`
	// LatMin, LatAvg and LatMax summarise the TLS phase of successful probes.
	LatMin *int64 `gorm:"column:lat_min"`
	LatAvg *int64 `gorm:"column:lat_avg"`
	LatMax *int64 `gorm:"column:lat_max"`
	// HandshakeMs is AWG only: the last successful cycle of the bucket.
	HandshakeMs *int64 `gorm:"column:handshake_ms"`
	// SentAt is ms UTC of the panel accepting the bucket, NULL until then.
	SentAt *int64 `gorm:"column:sent_at;index:idx_ms_stats_buckets_sent_at"`
}

// TableName pins the table name.
func (StatsBucket) TableName() string { return "stats_buckets" }

// ProbeSeen logs one tunnel probe arriving through a target's tunnel (spec
// §7.5). It is diagnostics only, kept for 24 hours; state is never derived
// from it.
type ProbeSeen struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	MonClientID string `gorm:"column:mon_client_id;size:64;not null;index:idx_ms_probe_seen_mon_client"`
	InboundKind string `gorm:"column:inbound_kind;size:16;not null"`
	InboundID   int64  `gorm:"column:inbound_id;not null"`
	Path        string `gorm:"column:path;size:16;not null"`
	// EgressIP is the source address the probe request arrived from.
	EgressIP string `gorm:"column:egress_ip;size:64;not null;default:''"`
	// SeenAt is ms UTC.
	SeenAt int64 `gorm:"column:seen_at;not null;index:idx_ms_probe_seen_seen_at"`
	// UnknownTarget marks a probe for a target this mon-client does not have
	// in its config: still answered 200, but flagged here (spec §7.5).
	UnknownTarget bool `gorm:"column:unknown_target;not null;default:false"`
}

// TableName pins the table name.
func (ProbeSeen) TableName() string { return "probe_seen" }
