package store

import (
	"errors"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// fakeStore is openTestStore with a Fake clock installed, so every
// session/lockout test drives the 24 h TTL and the 15 min lock by advancing
// time instead of sleeping (docs/agents/testing.md).
func fakeStore(t *testing.T) (*Store, *clock.Fake) {
	t.Helper()
	s := openTestStore(t)
	clk := clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	s.Clock = clk
	return s, clk
}

// TestSession_CreateAndResolve is the happy path: a fresh session resolves
// back to its row, and its id is long enough to be unguessable.
func TestSession_CreateAndResolve(t *testing.T) {
	s, _ := fakeStore(t)

	sess, err := s.CreateSession("203.0.113.5")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if len(sess.Id) < 40 {
		t.Fatalf("session id %q is shorter than 32 random bytes of base64url", sess.Id)
	}

	got, err := s.Session(sess.Id)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if got.Ip != "203.0.113.5" {
		t.Fatalf("session ip = %q, want 203.0.113.5", got.Ip)
	}
}

// TestSession_Expires proves spec §9.1's 24 h: the session is good right up
// to the boundary and dead past it.
func TestSession_Expires(t *testing.T) {
	s, clk := fakeStore(t)

	sess, err := s.CreateSession("203.0.113.5")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	clk.Advance(SessionTTL - time.Second)
	if _, err := s.Session(sess.Id); err != nil {
		t.Fatalf("Session just before the TTL: %v", err)
	}

	clk.Advance(2 * time.Second)
	if _, err := s.Session(sess.Id); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session after the TTL: err = %v, want ErrSessionNotFound", err)
	}
}

// TestSession_Delete covers Log out: the cookie stops working immediately,
// and deleting twice is not an error.
func TestSession_Delete(t *testing.T) {
	s, _ := fakeStore(t)

	sess, err := s.CreateSession("203.0.113.5")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := s.DeleteSession(sess.Id); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.Session(sess.Id); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session after logout: err = %v, want ErrSessionNotFound", err)
	}
	if err := s.DeleteSession(sess.Id); err != nil {
		t.Fatalf("second DeleteSession: %v", err)
	}
}

// TestSession_UnknownID: an id nobody ever issued is the same "not found" as
// an expired one.
func TestSession_UnknownID(t *testing.T) {
	s, _ := fakeStore(t)
	if _, err := s.Session("nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session(unknown): err = %v, want ErrSessionNotFound", err)
	}
	if _, err := s.Session(""); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session(\"\"): err = %v, want ErrSessionNotFound", err)
	}
}

// TestLoginAttempts_LockAfterFive walks spec §9.1's guard end to end: four
// failures leave the IP open with a shrinking budget, the fifth locks it for
// fifteen minutes, and the lock lapses on its own.
func TestLoginAttempts_LockAfterFive(t *testing.T) {
	s, clk := fakeStore(t)
	const ip = "198.51.100.7"

	for i := 1; i < MaxLoginFailures; i++ {
		locked, left, err := s.RecordLoginFailure(ip)
		if err != nil {
			t.Fatalf("RecordLoginFailure %d: %v", i, err)
		}
		if locked {
			t.Fatalf("locked after %d failures, want lock only at %d", i, MaxLoginFailures)
		}
		if want := MaxLoginFailures - i; left != want {
			t.Fatalf("after %d failures attemptsLeft = %d, want %d", i, left, want)
		}
	}

	locked, _, err := s.RecordLoginFailure(ip)
	if err != nil {
		t.Fatalf("RecordLoginFailure %d: %v", MaxLoginFailures, err)
	}
	if !locked {
		t.Fatalf("not locked after %d failures", MaxLoginFailures)
	}

	isLocked, left, err := s.LoginLocked(ip)
	if err != nil {
		t.Fatalf("LoginLocked: %v", err)
	}
	if !isLocked || left <= 0 || left > LoginLockout {
		t.Fatalf("LoginLocked = (%v, %v), want locked with a positive remaining ≤ %v", isLocked, left, LoginLockout)
	}

	clk.Advance(LoginLockout - time.Second)
	if isLocked, _, _ := s.LoginLocked(ip); !isLocked {
		t.Fatal("lock lapsed before 15 minutes")
	}
	clk.Advance(2 * time.Second)
	if isLocked, _, _ := s.LoginLocked(ip); isLocked {
		t.Fatal("lock did not lapse after 15 minutes")
	}
}

// TestLoginAttempts_ResetOnSuccess: a successful login clears the streak, so
// four failures yesterday plus one today never adds up to a lock.
func TestLoginAttempts_ResetOnSuccess(t *testing.T) {
	s, _ := fakeStore(t)
	const ip = "198.51.100.7"

	for range MaxLoginFailures - 1 {
		if _, _, err := s.RecordLoginFailure(ip); err != nil {
			t.Fatalf("RecordLoginFailure: %v", err)
		}
	}
	if err := s.ResetLoginAttempts(ip); err != nil {
		t.Fatalf("ResetLoginAttempts: %v", err)
	}

	locked, left, err := s.RecordLoginFailure(ip)
	if err != nil {
		t.Fatalf("RecordLoginFailure after reset: %v", err)
	}
	if locked {
		t.Fatal("locked on the first failure after a successful login")
	}
	if want := MaxLoginFailures - 1; left != want {
		t.Fatalf("attemptsLeft = %d, want %d", left, want)
	}
}

// TestLoginAttempts_PerIP: one IP's failures never lock another's, since the
// counter is keyed on the IP (spec §9.1) and mon-server has only one account
// to lock.
func TestLoginAttempts_PerIP(t *testing.T) {
	s, _ := fakeStore(t)

	for range MaxLoginFailures {
		if _, _, err := s.RecordLoginFailure("198.51.100.7"); err != nil {
			t.Fatalf("RecordLoginFailure: %v", err)
		}
	}
	if locked, _, _ := s.LoginLocked("203.0.113.5"); locked {
		t.Fatal("a second IP was locked out by the first IP's failures")
	}
}
