package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// SessionTTL is how long one admin UI login lasts (spec §9.1: "cookie-сессия
// mon_session ... на 24 ч"). It is the cookie's Max-Age as well as the row's
// expires_at, so a stolen cookie stops working at the same moment the row
// does even if a browser ignores the former.
const SessionTTL = 24 * time.Hour

// MaxLoginFailures and LoginLockout implement spec §9.1's brute-force guard:
// "5 неудачных логинов с IP → 15 мин блокировки". The counter is per source
// IP, not per account, because mon-server has exactly one account and
// locking it globally would let anyone lock the administrator out.
const (
	MaxLoginFailures = 5
	LoginLockout     = 15 * time.Minute
)

// sessionIDBytes is how much entropy a session id carries (spec §9.1 uses
// the same 32 random bytes as a client token, §6). base64url of 32 bytes is
// 43 characters, well inside AdminSession.Id's size:64.
const sessionIDBytes = 32

// ErrSessionNotFound is "no such session, or it has expired" — deliberately
// one error, not two: an admin UI request with an unknown cookie and one
// with a cookie that timed out both mean the same thing to the caller (send
// them to the login page), and telling them apart would only leak whether a
// given session id ever existed.
var ErrSessionNotFound = errors.New("store: admin session not found")

// CreateSession mints a new admin UI session for ip and stores it (spec
// §9.1). The returned row's Id is the opaque value that goes into the
// mon_session cookie; it is generated from crypto/rand, never derived from
// the username, the IP or the time, so it cannot be guessed from anything
// an attacker can observe.
func (s *Store) CreateSession(ip string) (*AdminSession, error) {
	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("store: generate session id: %w", err)
	}
	now := s.Clock.Now()
	sess := &AdminSession{
		Id:        base64.RawURLEncoding.EncodeToString(raw),
		CreatedAt: clock.Ms(now),
		ExpiresAt: clock.Ms(now.Add(SessionTTL)),
		Ip:        ip,
	}
	if err := s.DB.Create(sess).Error; err != nil {
		return nil, err
	}
	return sess, nil
}

// Session resolves a cookie value to its session row, refusing one that has
// already expired (spec §9.1's 24 h). Expiry is checked in SQL against the
// Clock rather than by a background sweep, so a session is dead the instant
// it times out even if the retention job (step 11) has not yet deleted the
// row.
func (s *Store) Session(id string) (*AdminSession, error) {
	if id == "" {
		return nil, ErrSessionNotFound
	}
	var sess AdminSession
	err := s.DB.Where("id = ? AND expires_at > ?", id, clock.Ms(s.Clock.Now())).First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// DeleteSession drops one session row — the admin UI's Log out (spec §9.1).
// Deleting rather than expiring it means a cookie a browser kept (or an
// attacker copied) stops working immediately, which is the whole point of a
// logout button. Deleting a session that is not there is not an error:
// logging out twice is not a failure.
func (s *Store) DeleteSession(id string) error {
	return s.DB.Where("id = ?", id).Delete(&AdminSession{}).Error
}

// LoginLocked reports whether ip is currently locked out and, if so, for how
// much longer (spec §9.1). The remaining duration is what the login page
// shows the administrator, so they know whether to wait or to go fix their
// password manager.
func (s *Store) LoginLocked(ip string) (bool, time.Duration, error) {
	var att LoginAttempt
	err := s.DB.First(&att, "ip = ?", ip).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	now := clock.Ms(s.Clock.Now())
	if att.LockedUntil > now {
		return true, time.Duration(att.LockedUntil-now) * time.Millisecond, nil
	}
	return false, 0, nil
}

// RecordLoginFailure counts one failed login from ip and locks the IP out
// for LoginLockout once MaxLoginFailures is reached (spec §9.1). It returns
// whether the IP is now locked and how many attempts are left before it
// would be, so the login page can show "N attempts left" exactly like the
// prototype does. Reaching the threshold resets the counter to zero: the
// lock itself is what stops further attempts, and after it lapses the IP
// gets a fresh set of five rather than being locked again on its very next
// mistake.
func (s *Store) RecordLoginFailure(ip string) (locked bool, attemptsLeft int, err error) {
	now := s.Clock.Now()

	var att LoginAttempt
	findErr := s.DB.First(&att, "ip = ?", ip).Error
	if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
		return false, 0, findErr
	}
	att.Ip = ip
	att.Failures++
	if att.Failures >= MaxLoginFailures {
		att.Failures = 0
		att.LockedUntil = clock.Ms(now.Add(LoginLockout))
		locked = true
	}

	if err := s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip"}},
		DoUpdates: clause.AssignmentColumns([]string{"failures", "locked_until"}),
	}).Create(&att).Error; err != nil {
		return false, 0, err
	}
	return locked, MaxLoginFailures - att.Failures, nil
}

// ResetLoginAttempts clears the failure counter and any lock for ip after a
// successful login (spec §9.1: "5 неудачных" means five in a row — a
// success in between starts the count over).
func (s *Store) ResetLoginAttempts(ip string) error {
	return s.DB.Where("ip = ?", ip).Delete(&LoginAttempt{}).Error
}
