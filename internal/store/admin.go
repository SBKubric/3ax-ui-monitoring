package store

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Errors returned by SetAdmin.
var (
	// ErrEmptyUsername reports an administrator name that is blank.
	ErrEmptyUsername = errors.New("username is empty")
	// ErrEmptyPassword reports a blank password.
	ErrEmptyPassword = errors.New("password is empty")
)

// missingAdminHash is compared against when no administrator row exists, so
// that a login attempt on a fresh installation costs the same as a wrong
// password and cannot be told apart by its timing.
var missingAdminHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("mon-server: no administrator configured"), bcrypt.DefaultCost)
	if err != nil {
		// GenerateFromPassword only fails on an invalid cost, which is a
		// constant here; a non-matching placeholder is still safe.
		return []byte("$2a$10$invalidplaceholderhashinvalidplaceholderhashinvalidplacehol")
	}
	return hash
})

// SetAdmin writes the single administrator row, replacing both the username
// and the password hash (spec §2: a repeat `admin set` changes the login).
// The password is stored as a bcrypt hash at bcrypt.DefaultCost.
func (s *Store) SetAdmin(username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return ErrEmptyUsername
	}
	if password == "" {
		return ErrEmptyPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: hash password: %w", err)
	}
	row := Admin{
		ID:           AdminRowID,
		Username:     username,
		PasswordHash: string(hash),
		UpdatedAt:    s.NowMS(),
	}
	err = s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"username", "password_hash", "updated_at"}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("store: write admin: %w", err)
	}
	return nil
}

// CheckAdmin reports whether username and password match the stored
// administrator. It returns false without an error when no administrator has
// been set yet.
func (s *Store) CheckAdmin(username, password string) (bool, error) {
	row, ok, err := s.Admin()
	if err != nil {
		return false, err
	}
	if !ok {
		// Spend the same time as a real check before refusing.
		_ = bcrypt.CompareHashAndPassword(missingAdminHash(), []byte(password))
		return false, nil
	}
	nameOK := subtle.ConstantTimeCompare([]byte(row.Username), []byte(username)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password)) == nil
	return nameOK && passOK, nil
}

// Admin returns the administrator row and whether one exists. The admin UI
// uses it to show who is logged in; the password hash never leaves the store.
func (s *Store) Admin() (Admin, bool, error) {
	var row Admin
	err := s.db.Where("id = ?", AdminRowID).Take(&row).Error
	switch {
	case err == nil:
		return row, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return Admin{}, false, nil
	default:
		return Admin{}, false, fmt.Errorf("store: read admin: %w", err)
	}
}
