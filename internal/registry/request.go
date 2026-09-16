package registry

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Submit files a registration request (mon-protocol.md §2.1). It validates the
// shape of the pairing code, applies the three rate limits of spec §6 and
// mints the polling secret; the administrator does the rest from the admin UI.
func (r *Registry) Submit(ctx context.Context, req SubmitRequest) (SubmitResult, error) {
	code := strings.TrimSpace(req.PairingCode)
	if !pairingCodePattern.MatchString(code) {
		return SubmitResult{}, ErrInvalidPairingCode
	}
	hostname := strings.TrimSpace(req.Hostname)
	if len(hostname) > maxHostnameLen {
		return SubmitResult{}, ErrHostnameTooLong
	}
	version := strings.TrimSpace(req.Version)
	if len(version) > maxVersionLen {
		return SubmitResult{}, ErrVersionTooLong
	}
	publicIP := strings.TrimSpace(req.PublicIP)
	if len(publicIP) > maxIPLen {
		return SubmitResult{}, ErrPublicIPTooLong
	}
	remoteIP := strings.TrimSpace(req.RemoteIP)
	if len(remoteIP) > maxIPLen {
		remoteIP = remoteIP[:maxIPLen]
	}

	// One decision at a time: the limits are counted and the row written
	// under the same lock, so two boxes racing cannot both pass the last free
	// slot.
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowMS()
	if err := r.expireStale(ctx, now); err != nil {
		return SubmitResult{}, err
	}
	if err := r.checkLimits(ctx, remoteIP, now); err != nil {
		return SubmitResult{}, err
	}

	id, err := randomBase64(requestIDBytes)
	if err != nil {
		return SubmitResult{}, err
	}
	row := store.RegistrationRequest{
		RequestID:   id,
		PairingCode: code,
		Hostname:    hostname,
		Version:     version,
		PublicIP:    publicIP,
		RemoteIP:    remoteIP,
		Status:      store.RequestPending,
		CreatedAt:   now,
		ExpiresAt:   now + RequestTTL.Milliseconds(),
	}
	if err := r.st.DB().WithContext(ctx).Create(&row).Error; err != nil {
		return SubmitResult{}, fmt.Errorf("registry: create registration request: %w", err)
	}
	// The requestId is the polling secret and never reaches the log; the
	// pairing code is what the administrator matches against the box.
	r.log.Info("registration request received",
		"remoteIp", remoteIP, "publicIp", publicIP, "hostname", hostname,
		"version", version, "pairingCode", code)

	return SubmitResult{RequestID: id, PollAfterMS: PollAfterMS, ExpiresAt: row.ExpiresAt}, nil
}

// Poll answers the mon-client's GET /v1/register/{requestId}
// (mon-protocol.md §2.2). An approved request hands out its token exactly
// once: the plaintext is cleared in the same statement that reads it, so a
// second poll returns approved with no token.
func (r *Registry) Poll(ctx context.Context, requestID string) (PollResult, error) {
	if requestID == "" {
		return PollResult{}, ErrRequestNotFound
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowMS()
	db := r.st.DB().WithContext(ctx)
	var row store.RegistrationRequest
	err := db.Where("request_id = ?", requestID).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return PollResult{}, ErrRequestNotFound
	case err != nil:
		return PollResult{}, fmt.Errorf("registry: read registration request: %w", err)
	}

	switch row.Status {
	case store.RequestPending:
		// A pending row past its deadline is expired on read; the retention
		// job only sweeps what nobody polls.
		if row.ExpiresAt <= now {
			if err := r.expireOne(ctx, requestID); err != nil {
				return PollResult{}, err
			}
			return PollResult{}, ErrRequestExpired
		}
		return PollResult{Status: store.RequestPending}, nil

	case store.RequestApproved:
		// The deadline no longer applies once the administrator has decided:
		// the box must be able to collect the token it was granted.
		token := row.ApprovedToken
		if token != "" {
			res := db.Model(&store.RegistrationRequest{}).
				Where("request_id = ? AND approved_token = ?", requestID, token).
				Update("approved_token", "")
			if res.Error != nil {
				return PollResult{}, fmt.Errorf("registry: clear issued token: %w", res.Error)
			}
			if res.RowsAffected == 0 {
				// Another poll collected it first; this one gets no token.
				token = ""
			} else {
				r.log.Info("client token collected", "monClientId", row.MonClientID)
			}
		}
		return PollResult{Status: store.RequestApproved, MonClientID: row.MonClientID, Token: token}, nil

	case store.RequestRejected:
		return PollResult{Status: store.RequestRejected}, nil

	default:
		return PollResult{}, ErrRequestExpired
	}
}

// checkLimits applies the three limits of spec §6 in order of how specific
// they are, so the mon-client is told the narrowest reason it hit.
func (r *Registry) checkLimits(ctx context.Context, remoteIP string, now int64) error {
	db := r.st.DB().WithContext(ctx)

	var lastCreated int64
	err := db.Model(&store.RegistrationRequest{}).
		Where("remote_ip = ?", remoteIP).
		Select("COALESCE(MAX(created_at), 0)").
		Row().Scan(&lastCreated)
	if err != nil {
		return fmt.Errorf("registry: read last request of %s: %w", remoteIP, err)
	}
	if wait := time.Duration(lastCreated+MinSubmitInterval.Milliseconds()-now) * time.Millisecond; lastCreated > 0 && wait > 0 {
		return &RateLimitError{Limit: ErrIPRateLimited, Wait: capWait(wait)}
	}

	var pendingForIP int64
	if err := db.Model(&store.RegistrationRequest{}).
		Where("status = ? AND remote_ip = ?", store.RequestPending, remoteIP).
		Count(&pendingForIP).Error; err != nil {
		return fmt.Errorf("registry: count pending requests of %s: %w", remoteIP, err)
	}
	if pendingForIP >= MaxPendingPerIP {
		wait, err := r.waitForSlot(ctx, remoteIP, now)
		if err != nil {
			return err
		}
		return &RateLimitError{Limit: ErrTooManyPendingForIP, Wait: wait}
	}

	var pendingTotal int64
	if err := db.Model(&store.RegistrationRequest{}).
		Where("status = ?", store.RequestPending).
		Count(&pendingTotal).Error; err != nil {
		return fmt.Errorf("registry: count pending requests: %w", err)
	}
	if pendingTotal >= MaxPendingTotal {
		wait, err := r.waitForSlot(ctx, "", now)
		if err != nil {
			return err
		}
		return &RateLimitError{Limit: ErrTooManyPendingGlobal, Wait: wait}
	}
	return nil
}

// waitForSlot is how long until the oldest pending request frees a slot: the
// honest Retry-After for a queue that is full. remoteIP narrows it to one
// box's own queue, an empty remoteIP looks at all of them.
func (r *Registry) waitForSlot(ctx context.Context, remoteIP string, now int64) (time.Duration, error) {
	q := r.st.DB().WithContext(ctx).Model(&store.RegistrationRequest{}).
		Where("status = ?", store.RequestPending)
	if remoteIP != "" {
		q = q.Where("remote_ip = ?", remoteIP)
	}
	var earliest int64
	if err := q.Select("COALESCE(MIN(expires_at), 0)").Row().Scan(&earliest); err != nil {
		return 0, fmt.Errorf("registry: read earliest pending deadline: %w", err)
	}
	if earliest == 0 {
		return capWait(MinSubmitInterval), nil
	}
	return capWait(time.Duration(earliest-now) * time.Millisecond), nil
}

// expireStale moves every pending request past its deadline to expired, so
// that the rate limits count only requests an administrator could still act
// on.
func (r *Registry) expireStale(ctx context.Context, now int64) error {
	err := r.st.DB().WithContext(ctx).Model(&store.RegistrationRequest{}).
		Where("status = ? AND expires_at <= ?", store.RequestPending, now).
		Update("status", store.RequestExpired).Error
	if err != nil {
		return fmt.Errorf("registry: expire stale requests: %w", err)
	}
	return nil
}

// expireOne marks a single pending request expired.
func (r *Registry) expireOne(ctx context.Context, requestID string) error {
	err := r.st.DB().WithContext(ctx).Model(&store.RegistrationRequest{}).
		Where("request_id = ? AND status = ?", requestID, store.RequestPending).
		Update("status", store.RequestExpired).Error
	if err != nil {
		return fmt.Errorf("registry: expire request: %w", err)
	}
	return nil
}

// takePendingRequest reads the request an administrator is deciding on,
// refusing one that is already decided and one whose five minutes ran out
// while the page was open. It only reads: the decision that called it runs in
// a transaction that is about to be rolled back, so recording the deadline is
// settleExpired's job afterwards.
func takePendingRequest(tx *gorm.DB, requestID string, now int64) (store.RegistrationRequest, error) {
	var row store.RegistrationRequest
	err := tx.Where("request_id = ?", requestID).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.RegistrationRequest{}, ErrRequestNotFound
	case err != nil:
		return store.RegistrationRequest{}, fmt.Errorf("registry: read registration request: %w", err)
	}
	if row.Status != store.RequestPending {
		if row.Status == store.RequestExpired {
			return store.RegistrationRequest{}, ErrRequestExpired
		}
		return store.RegistrationRequest{}, ErrRequestNotPending
	}
	if row.ExpiresAt <= now {
		return store.RegistrationRequest{}, ErrRequestExpired
	}
	return row, nil
}

// settleExpired records the deadline a decision ran into. The transaction that
// found it was rolled back, so the row would otherwise stay pending and keep
// occupying a rate-limit slot; the administrator still gets the original
// error.
func (r *Registry) settleExpired(ctx context.Context, requestID string, err error) error {
	if errors.Is(err, ErrRequestExpired) {
		if markErr := r.expireOne(ctx, requestID); markErr != nil {
			r.log.Error("could not mark a registration request expired", "err", markErr)
		}
	}
	return err
}

// randomBase64 returns n bytes of crypto/rand in unpadded base64url, the form
// of both the requestId and the client token.
func randomBase64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("registry: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
