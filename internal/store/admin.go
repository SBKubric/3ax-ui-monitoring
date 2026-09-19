package store

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// dummyPasswordHash is compared against on every CheckAdmin call where the
// real hash cannot be used — no admin row yet, or a username that does not
// match — so that "no such admin" and "wrong password" both pay for exactly
// one bcrypt comparison. Without this, an attacker could tell the two apart
// by response time before any admin has even been set. The password hashed
// here is never used to log in; only the shape of the comparison matters.
//
// This is a precomputed bcrypt (cost 10, bcrypt.DefaultCost) hash of the
// plaintext "mon-server-timing-safety-placeholder", generated once offline.
// It used to be computed at package init via bcrypt.GenerateFromPassword,
// but that runs a full cost-10 bcrypt hash (tens of milliseconds) at the
// start of every binary that imports this package — `mon-server version`,
// `mon-server --help`, and both this package's and cmd/mon-server's test
// binaries — for a value that never changes. A literal costs nothing at
// startup.
const dummyPasswordHash = "$2a$10$L5N3zyFg4ipFYxk739CYMuudP6Fi.4xzvLcb60jjfuM5BzBbU.s3."

// SetAdmin (re)writes mon-server's one administrator account: `mon-server
// admin set <user>` (spec §2). It always replaces the single admin row
// outright, so a second call changes both the login and the password at
// once, matching the CLI's documented behaviour ("повторный вызов меняет
// логин и пароль") — there is deliberately no way to change just one of the
// two.
func (s *Store) SetAdmin(username, password string) error {
	if username == "" {
		return errors.New("store: username must not be empty")
	}
	if password == "" {
		return errors.New("store: password must not be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: hash password: %w", err)
	}

	admin := Admin{
		Id:           adminRowId,
		Username:     username,
		PasswordHash: string(hash),
		// s.Clock is clock.Real{} in production (see Open) and a
		// clock.NewFake in tests, so this timestamp is exercised
		// deterministically instead of racing the wall clock.
		UpdatedAt: clock.Ms(s.Clock.Now()),
	}
	return s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"username", "password_hash", "updated_at"}),
	}).Create(&admin).Error
}

// CheckAdmin reports whether username/password match the stored admin
// account. It always performs exactly one bcrypt comparison before
// returning — against the real hash when username matches, against
// dummyPasswordHash otherwise — so a caller cannot distinguish "wrong
// password" from "no such username" (there is only ever one username, but
// admin/login handlers built in step 10 use the same shape) by timing.
func (s *Store) CheckAdmin(username, password string) (bool, error) {
	var admin Admin
	err := s.DB.First(&admin, "id = ?", adminRowId).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
		return false, nil
	}
	if err != nil {
		return false, err
	}

	hash := []byte(dummyPasswordHash)
	usernameMatches := admin.Username == username
	if usernameMatches {
		hash = []byte(admin.PasswordHash)
	}

	cmpErr := bcrypt.CompareHashAndPassword(hash, []byte(password))
	if !usernameMatches || cmpErr != nil {
		if cmpErr != nil && !errors.Is(cmpErr, bcrypt.ErrMismatchedHashAndPassword) {
			return false, fmt.Errorf("store: compare password: %w", cmpErr)
		}
		return false, nil
	}
	return true, nil
}
