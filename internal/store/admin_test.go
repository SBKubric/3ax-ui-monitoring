package store

import (
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// TestAdmin_SetThenCheck checks the basic happy path: after `admin set`, the
// same credentials check out and a wrong password does not.
func TestAdmin_SetThenCheck(t *testing.T) {
	s := openTestStore(t)

	if err := s.SetAdmin("alice", "correct horse battery staple"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	ok, err := s.CheckAdmin("alice", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Fatal("CheckAdmin with correct credentials: want true, got false")
	}

	ok, err = s.CheckAdmin("alice", "wrong password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if ok {
		t.Fatal("CheckAdmin with wrong password: want false, got true")
	}
}

// TestAdmin_CheckUnknownUsername checks that a username that has never been
// set fails cleanly (no error, no match) rather than panicking on a missing
// row.
func TestAdmin_CheckUnknownUsername(t *testing.T) {
	s := openTestStore(t)

	ok, err := s.CheckAdmin("nobody", "whatever")
	if err != nil {
		t.Fatalf("CheckAdmin on empty admin table: %v", err)
	}
	if ok {
		t.Fatal("CheckAdmin with no admin set: want false, got true")
	}

	if err := s.SetAdmin("alice", "correct horse battery staple"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}
	ok, err = s.CheckAdmin("bob", "correct horse battery staple")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if ok {
		t.Fatal("CheckAdmin with wrong username: want false, got true")
	}
}

// TestAdmin_SecondSetChangesLoginAndPassword checks the spec's documented
// behaviour for a repeat `admin set` call (§2: "повторный вызов меняет
// логин и пароль"): the old username must stop working entirely, not just
// gain a second valid identity.
func TestAdmin_SecondSetChangesLoginAndPassword(t *testing.T) {
	s := openTestStore(t)

	if err := s.SetAdmin("alice", "first password"); err != nil {
		t.Fatalf("first SetAdmin: %v", err)
	}
	if err := s.SetAdmin("bob", "second password"); err != nil {
		t.Fatalf("second SetAdmin: %v", err)
	}

	ok, err := s.CheckAdmin("bob", "second password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Fatal("CheckAdmin(bob, second password): want true, got false")
	}

	ok, err = s.CheckAdmin("alice", "first password")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if ok {
		t.Fatal("CheckAdmin(alice, first password) after replacement: want false, got true")
	}

	var count int64
	if err := s.DB.Model(&Admin{}).Count(&count).Error; err != nil {
		t.Fatalf("count admin rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin row count = %d, want 1 (replace, not append)", count)
	}
}

// TestSetAdmin_UsesStoreClock checks that SetAdmin stamps UpdatedAt from
// s.Clock rather than a bare time.Now(), so a test can drive it
// deterministically via clock.NewFake instead of racing the wall clock — and
// so a later step that injects a real clock.Clock gets one seam, not two.
func TestSetAdmin_UsesStoreClock(t *testing.T) {
	s := openTestStore(t)

	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.Clock = clock.NewFake(t0)

	if err := s.SetAdmin("alice", "correct horse battery staple"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	var admin Admin
	if err := s.DB.First(&admin, "id = ?", adminRowId).Error; err != nil {
		t.Fatalf("read back admin: %v", err)
	}
	if admin.UpdatedAt != clock.Ms(t0) {
		t.Fatalf("UpdatedAt = %d, want %d (clock.Ms(t0))", admin.UpdatedAt, clock.Ms(t0))
	}
}

// TestSetAdmin_RejectsEmptyUsernameOrPassword checks input validation: an
// empty username or password would otherwise silently produce an
// unusable-but-present admin account.
func TestSetAdmin_RejectsEmptyUsernameOrPassword(t *testing.T) {
	s := openTestStore(t)

	if err := s.SetAdmin("", "password"); err == nil {
		t.Fatal("SetAdmin with empty username: want error, got nil")
	}
	if err := s.SetAdmin("alice", ""); err == nil {
		t.Fatal("SetAdmin with empty password: want error, got nil")
	}
}
