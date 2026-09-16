package registry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// ApproveInput is what the administrator fills in when approving a new
// mon-client (spec §9.2). Paths may be empty, meaning both.
type ApproveInput struct {
	Name   string
	Region string
	Paths  []string
}

// ApproveResult describes the registry row an approval created or refreshed.
// It deliberately does not carry the client token: the plaintext goes to the
// mon-client's next poll and nowhere else (spec §6).
type ApproveResult struct {
	MonClientID string
	Name        string
	Region      string
	Paths       []string
	// Replacement is true when an existing mon-client was re-keyed rather
	// than a new one created.
	Replacement bool
	// ApprovedAt is ms UTC of the approval.
	ApprovedAt int64
}

// PendingRequest is one waiting registration request as the admin UI shows it
// (spec §9.2).
type PendingRequest struct {
	RequestID   string
	PairingCode string
	Hostname    string
	Version     string
	PublicIP    string
	RemoteIP    string
	// CreatedAt and ExpiresAt are ms UTC; the UI counts the deadline down.
	CreatedAt int64
	ExpiresAt int64
	// Matches are the existing mon-clients this request looks like, so the UI
	// can offer "same hostname as msk-1: replacement?". It is a hint only:
	// the administrator picks the mode explicitly.
	Matches []ReplacementHint
}

// ReplacementHint names one existing mon-client a pending request resembles,
// and why.
type ReplacementHint struct {
	MonClientID string
	Name        string
	Region      string
	// ByHostname is set when the request comes from a hostname this
	// mon-client was registered under before.
	ByHostname bool
	// ByPublicIP is set when the addresses match.
	ByPublicIP bool
}

// Approve accepts a registration request as a brand new mon-client: it derives
// a unique id from the name, issues a client token, keeps only its SHA-256 and
// leaves the plaintext in the request for the box's next poll (spec §6).
func (r *Registry) Approve(ctx context.Context, requestID string, in ApproveInput) (ApproveResult, error) {
	name := strings.TrimSpace(in.Name)
	base := Slug(name)
	if base == "" {
		return ApproveResult{}, ErrEmptyName
	}
	paths, err := normalisePaths(in.Paths)
	if err != nil {
		return ApproveResult{}, err
	}
	encodedPaths, err := store.EncodePaths(paths)
	if err != nil {
		return ApproveResult{}, err
	}
	region := strings.TrimSpace(in.Region)

	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.nowMS()

	var result ApproveResult
	err = r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		req, err := takePendingRequest(tx, requestID, now)
		if err != nil {
			return err
		}
		id, err := uniqueMonClientID(tx, base)
		if err != nil {
			return err
		}
		token, err := randomBase64(tokenBytes)
		if err != nil {
			return err
		}
		mc := store.MonClient{
			ID:         id,
			Name:       name,
			Region:     region,
			Paths:      encodedPaths,
			TokenHash:  store.HashToken(token),
			Enabled:    true,
			State:      store.ClientStateNever,
			Version:    req.Version,
			RemoteIP:   req.RemoteIP,
			ApprovedAt: now,
		}
		if err := tx.Create(&mc).Error; err != nil {
			return fmt.Errorf("registry: create mon-client %s: %w", id, err)
		}
		if err := decideRequest(tx, requestID, store.RequestApproved, id, token); err != nil {
			return err
		}
		result = ApproveResult{MonClientID: id, Name: name, Region: region, Paths: paths, ApprovedAt: now}
		return nil
	})
	if err != nil {
		return ApproveResult{}, r.settleExpired(ctx, requestID, err)
	}
	r.log.Info("registration request approved", "monClientId", result.MonClientID, "region", region, "paths", paths)
	return result, nil
}

// ApproveAsReplacement accepts a registration request as the new box behind an
// existing mon-client (spec §6). The row keeps its id, name, region, paths and
// history — its targets and statistics stay — and only the token is replaced,
// which revokes the old one. The state goes back to NEVER and everything the
// previous box reported about itself is cleared, because none of it describes
// the machine now answering.
func (r *Registry) ApproveAsReplacement(ctx context.Context, requestID, monClientID string) (ApproveResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.nowMS()

	var result ApproveResult
	err := r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		req, err := takePendingRequest(tx, requestID, now)
		if err != nil {
			return err
		}
		var mc store.MonClient
		switch err := tx.Where("id = ?", monClientID).Take(&mc).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return ErrMonClientNotFound
		case err != nil:
			return fmt.Errorf("registry: read mon-client %s: %w", monClientID, err)
		}
		token, err := randomBase64(tokenBytes)
		if err != nil {
			return err
		}
		// enabled is left as it is: replacing the box does not undo an
		// administrator's decision to keep this mon-client switched off.
		updates := map[string]any{
			"token_hash":        store.HashToken(token),
			"state":             store.ClientStateNever,
			"last_heartbeat":    int64(0),
			"missed_heartbeats": 0,
			"applied_revision":  "",
			"config_error":      "",
			"config_error_at":   int64(0),
			"version":           req.Version,
			"xray_version":      "",
			"remote_ip":         req.RemoteIP,
			"approved_at":       now,
		}
		if err := tx.Model(&store.MonClient{}).Where("id = ?", mc.ID).Updates(updates).Error; err != nil {
			return fmt.Errorf("registry: re-key mon-client %s: %w", mc.ID, err)
		}
		if err := decideRequest(tx, requestID, store.RequestApproved, mc.ID, token); err != nil {
			return err
		}
		paths, err := store.DecodePaths(mc.Paths)
		if err != nil {
			return err
		}
		result = ApproveResult{
			MonClientID: mc.ID,
			Name:        mc.Name,
			Region:      mc.Region,
			Paths:       paths,
			Replacement: true,
			ApprovedAt:  now,
		}
		return nil
	})
	if err != nil {
		return ApproveResult{}, r.settleExpired(ctx, requestID, err)
	}
	r.log.Info("registration request approved as replacement", "monClientId", result.MonClientID)
	return result, nil
}

// Reject turns a pending request down (spec §6): the mon-client learns it on
// its next poll and waits an hour before filing a new one.
func (r *Registry) Reject(ctx context.Context, requestID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.nowMS()

	err := r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := takePendingRequest(tx, requestID, now); err != nil {
			return err
		}
		return decideRequest(tx, requestID, store.RequestRejected, "", "")
	})
	if err != nil {
		return r.settleExpired(ctx, requestID, err)
	}
	r.log.Info("registration request rejected")
	return nil
}

// Pending lists the requests waiting for a decision, newest first, each with
// the mon-clients it might be replacing (spec §9.2).
func (r *Registry) Pending(ctx context.Context) ([]PendingRequest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowMS()
	if err := r.expireStale(ctx, now); err != nil {
		return nil, err
	}
	var rows []store.RegistrationRequest
	err := r.st.DB().WithContext(ctx).
		Where("status = ?", store.RequestPending).
		Order("created_at DESC, request_id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("registry: list pending requests: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	index, err := r.replacementIndex(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PendingRequest, 0, len(rows))
	for _, row := range rows {
		out = append(out, PendingRequest{
			RequestID:   row.RequestID,
			PairingCode: row.PairingCode,
			Hostname:    row.Hostname,
			Version:     row.Version,
			PublicIP:    row.PublicIP,
			RemoteIP:    row.RemoteIP,
			CreatedAt:   row.CreatedAt,
			ExpiresAt:   row.ExpiresAt,
			Matches:     index.match(row),
		})
	}
	return out, nil
}

// decideRequest records the administrator's decision on a request. For an
// approval it also parks the one-shot token plaintext.
func decideRequest(tx *gorm.DB, requestID, status, monClientID, token string) error {
	updates := map[string]any{
		"status":         status,
		"mon_client_id":  monClientID,
		"approved_token": token,
	}
	err := tx.Model(&store.RegistrationRequest{}).Where("request_id = ?", requestID).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("registry: decide registration request: %w", err)
	}
	return nil
}

// replacementIndex is the lookup behind the admin UI's replacement hint: which
// mon-client was registered from which hostname and which address. A
// mon-client carries no hostname of its own, so the hostnames come from the
// requests that were approved for it.
type replacementIndex struct {
	clients    map[string]store.MonClient
	byHostname map[string][]string
	byIP       map[string][]string
}

func (r *Registry) replacementIndex(ctx context.Context) (replacementIndex, error) {
	db := r.st.DB().WithContext(ctx)
	ix := replacementIndex{
		clients:    map[string]store.MonClient{},
		byHostname: map[string][]string{},
		byIP:       map[string][]string{},
	}
	var clients []store.MonClient
	if err := db.Find(&clients).Error; err != nil {
		return replacementIndex{}, fmt.Errorf("registry: list mon-clients: %w", err)
	}
	for _, mc := range clients {
		ix.clients[mc.ID] = mc
		ix.addIP(mc.RemoteIP, mc.ID)
	}
	if len(clients) == 0 {
		return ix, nil
	}
	var approved []store.RegistrationRequest
	err := db.Where("status = ? AND mon_client_id <> ''", store.RequestApproved).Find(&approved).Error
	if err != nil {
		return replacementIndex{}, fmt.Errorf("registry: list approved requests: %w", err)
	}
	for _, req := range approved {
		if _, ok := ix.clients[req.MonClientID]; !ok {
			continue
		}
		ix.addHostname(req.Hostname, req.MonClientID)
		ix.addIP(req.PublicIP, req.MonClientID)
		ix.addIP(req.RemoteIP, req.MonClientID)
	}
	return ix, nil
}

func (ix replacementIndex) addHostname(hostname, id string) {
	key := strings.ToLower(strings.TrimSpace(hostname))
	if key == "" {
		return
	}
	ix.byHostname[key] = appendUnique(ix.byHostname[key], id)
}

func (ix replacementIndex) addIP(ip, id string) {
	key := strings.TrimSpace(ip)
	if key == "" {
		return
	}
	ix.byIP[key] = appendUnique(ix.byIP[key], id)
}

// match returns the hints for one pending request, ordered by mon-client id.
func (ix replacementIndex) match(req store.RegistrationRequest) []ReplacementHint {
	hints := map[string]*ReplacementHint{}
	mark := func(id string, byHostname, byPublicIP bool) {
		mc, ok := ix.clients[id]
		if !ok {
			return
		}
		hint, ok := hints[id]
		if !ok {
			hint = &ReplacementHint{MonClientID: mc.ID, Name: mc.Name, Region: mc.Region}
			hints[id] = hint
		}
		hint.ByHostname = hint.ByHostname || byHostname
		hint.ByPublicIP = hint.ByPublicIP || byPublicIP
	}
	for _, id := range ix.byHostname[strings.ToLower(strings.TrimSpace(req.Hostname))] {
		mark(id, true, false)
	}
	for _, ip := range []string{req.PublicIP, req.RemoteIP} {
		for _, id := range ix.byIP[strings.TrimSpace(ip)] {
			mark(id, false, true)
		}
	}
	if len(hints) == 0 {
		return nil
	}
	out := make([]ReplacementHint, 0, len(hints))
	for _, hint := range hints {
		out = append(out, *hint)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MonClientID < out[j].MonClientID })
	return out
}

func appendUnique(ids []string, id string) []string {
	for _, existing := range ids {
		if existing == id {
			return ids
		}
	}
	return append(ids, id)
}
