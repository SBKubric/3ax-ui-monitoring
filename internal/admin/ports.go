package admin

import (
	"context"
	"errors"
)

// Sentinel errors the injected services may return so that a handler can pick
// the right status. Anything else is reported as an internal failure.
var (
	// ErrNotFound means the registration request or mon-client named in the
	// path does not exist: 404.
	ErrNotFound = errors.New("admin: not found")
	// ErrConflict means the operation clashes with the current state, for
	// example a mon-client id that is already taken: 409.
	ErrConflict = errors.New("admin: conflict")
	// ErrInvalid means the service refused the arguments the form produced,
	// after this package's own validation let them through: 400.
	ErrInvalid = errors.New("admin: invalid argument")
)

// Match reasons for the replacement hint of spec §9.2.
const (
	// MatchHostname means the request reports the hostname of an existing
	// mon-client.
	MatchHostname = "hostname"
	// MatchIP means the request comes from, or reports, the address of an
	// existing mon-client.
	MatchIP = "ip"
)

// Registry is the mon-client registry as the admin UI drives it (spec §6,
// §9.2, §9.3): pending registration requests, approval (including approval as
// a replacement), rejection, and the registry table with its per-row
// operations.
//
// internal/registry owns the behaviour; the wiring layer adapts it to this
// interface, so the admin UI can be tested with a fake and neither package
// imports the other.
type Registry interface {
	// PendingRequests returns the pending registration requests, newest
	// first, each with the replacement hints of §9.2.
	PendingRequests(ctx context.Context) ([]PendingRequest, error)
	// PendingCount is the number behind the badge on the Requests menu item.
	PendingCount(ctx context.Context) (int, error)
	// Approve approves a request, either as a new mon-client or as the
	// replacement of an existing one, and returns the resulting registry row.
	Approve(ctx context.Context, a Approval) (Client, error)
	// Reject marks a request rejected (§6: the mon-client then waits an hour).
	Reject(ctx context.Context, requestID string) error
	// Clients returns the registry, ordered by id.
	Clients(ctx context.Context) ([]Client, error)
	// UpdateClient edits name, region and paths. The id never changes.
	UpdateClient(ctx context.Context, id string, e ClientEdit) error
	// SetClientEnabled flips the Enabled switch (§6: disabling moves the
	// mon-client's targets to UNKNOWN, it stays in the registry snapshot).
	SetClientEnabled(ctx context.Context, id string, enabled bool) error
	// RevokeClient clears the token hash: the box gets 401, wipes its state
	// and files a fresh registration request (§6).
	RevokeClient(ctx context.Context, id string) error
	// DeleteClient removes the mon-client and its targets (§6).
	DeleteClient(ctx context.Context, id string) error
}

// PendingRequest is one pending registration request as the Requests page
// shows it (spec §9.2).
type PendingRequest struct {
	RequestID   string `json:"requestId"`
	PairingCode string `json:"pairingCode"`
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	// PublicIP is the address the box reports, RemoteIP the one the request
	// arrived from; they differ behind NAT.
	PublicIP string `json:"publicIp"`
	RemoteIP string `json:"remoteIp"`
	// CreatedAt and ExpiresAt are ms UTC; the page renders "expires mm:ss /
	// received N ago" from them against ServerTime.
	CreatedAt int64 `json:"createdAt"`
	ExpiresAt int64 `json:"expiresAt"`
	// Attempt is how many times this box has filed a request, the "attempt N"
	// under the hostname.
	Attempt int `json:"attempt"`
	// Matches are the existing mon-clients this request looks like. A
	// non-empty list highlights the row and suggests a replacement; the
	// administrator still chooses the mode explicitly (§6).
	Matches []ReplacementHint `json:"matches"`
}

// ReplacementHint names an existing mon-client a pending request resembles.
type ReplacementHint struct {
	MonClientID string `json:"monClientId"`
	Name        string `json:"name"`
	// Reason is MatchHostname or MatchIP.
	Reason string `json:"reason"`
}

// Approval is an approve or approve-as-replacement, as the modal of §9.2
// produced it. The admin UI validates the shape; the registry decides the id,
// issues the token and, in replacement mode, keeps the existing record's id,
// history, name, region and paths (§6).
type Approval struct {
	RequestID string `json:"-"`
	// Replace is true for "Approve as replacement" (mode "replace" on the
	// wire), false for a new mon-client.
	Replace bool `json:"replace"`
	// MonClientID is the record being replaced. It is empty unless Replace.
	MonClientID string   `json:"monClientId"`
	Name        string   `json:"name"`
	Region      string   `json:"region"`
	Paths       []string `json:"paths"`
}

// ClientEdit is the Edit modal of §9.3. The id is not in it: it never changes.
type ClientEdit struct {
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`
}

// Client is one registry row as the mon-clients table of §9.3 shows it.
// Nothing about targets is in it: the state of targets belongs to the panel's
// Monitoring page and is deliberately absent from the admin UI (spec §1).
type Client struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`
	// Enabled is the switch of §9.3; State is ONLINE, OFFLINE or NEVER.
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	// LastHeartbeat and ApprovedAt are ms UTC, 0 when there is none. A
	// mon-client that has never been seen shows "approved N ago" instead.
	LastHeartbeat int64  `json:"lastHeartbeat"`
	ApprovedAt    int64  `json:"approvedAt"`
	Version       string `json:"version"`
	XrayVersion   string `json:"xrayVersion"`
	// AppliedRevision is the config revision the box reports running,
	// ConfigRevision the one mon-server built for it; they differ while a new
	// config is on its way (§7.1).
	AppliedRevision string `json:"appliedRevision"`
	ConfigRevision  string `json:"configRevision"`
	// ConfigError is the last error the box reported applying its config,
	// shown in full in a tooltip and in the Edit modal.
	ConfigError   string `json:"configError"`
	ConfigErrorAt int64  `json:"configErrorAt"`
	RemoteIP      string `json:"remoteIp"`
	// TokenRevoked is true once the token hash has been cleared: the box will
	// file a fresh request, to be approved as a replacement (§6).
	TokenRevoked bool `json:"tokenRevoked"`
}

// PanelChecker runs the Check button of the Real server tab (§9.4): one
// GET /state with the values as typed, saving nothing. internal/panel makes
// the call; the wiring layer builds a throwaway client from the two arguments.
type PanelChecker interface {
	CheckPanel(ctx context.Context, panelURL, monToken string) (PanelCheck, error)
}

// PanelCheck is what a successful Check found.
type PanelCheck struct {
	Revision        string `json:"revision"`
	Inbounds        int    `json:"inbounds"`
	OverrideEnabled bool   `json:"overrideEnabled"`
	OverrideHost    string `json:"overrideHost"`
	PanelVersion    string `json:"panelVersion"`
}

// TelegramTester runs the Send test button of the Telegram tab (§9.4) with the
// values as typed, saving nothing. internal/tg delivers the message.
type TelegramTester interface {
	SendTestMessage(ctx context.Context, tgToken, tgChatID string) error
}

// ConfigRebuilder rebuilds every mon-client's configuration document, which
// gives each of them a new config revision (§5). Saving settings calls it when
// a probe parameter or realHost changed (§9.4). internal/clientcfg implements
// it.
type ConfigRebuilder interface {
	RebuildAll(ctx context.Context) error
}
