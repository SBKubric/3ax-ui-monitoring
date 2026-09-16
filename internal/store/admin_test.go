package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

func TestSetAdminStoresABcryptHash(t *testing.T) {
	s, fake := openTestStore(t)
	fake.Advance(2 * time.Minute)

	if err := s.SetAdmin("root", "correct horse"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}
	row, ok, err := s.Admin()
	if err != nil {
		t.Fatalf("Admin: %v", err)
	}
	if !ok {
		t.Fatal("Admin reports no administrator after SetAdmin")
	}
	if row.Username != "root" {
		t.Errorf("username = %q, want %q", row.Username, "root")
	}
	if strings.Contains(row.PasswordHash, "correct horse") {
		t.Fatal("the password is stored in clear")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte("correct horse")); err != nil {
		t.Errorf("stored hash does not verify the password: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte("wrong horse")); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Errorf("stored hash verified the wrong password: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(row.PasswordHash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Errorf("bcrypt cost = %d, want %d", cost, bcrypt.DefaultCost)
	}
	if want := clock.MS(testTime.Add(2 * time.Minute)); row.UpdatedAt != want {
		t.Errorf("updated_at = %d, want %d (the injected clock)", row.UpdatedAt, want)
	}
}

func TestCheckAdmin(t *testing.T) {
	s, _ := openTestStore(t)

	if ok, err := s.CheckAdmin("root", "correct horse"); err != nil || ok {
		t.Errorf("CheckAdmin without an administrator = %v, %v, want false, nil", ok, err)
	}
	if err := s.SetAdmin("root", "correct horse"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "right username and password", username: "root", password: "correct horse", want: true},
		{name: "wrong password", username: "root", password: "wrong horse"},
		{name: "wrong username", username: "admin", password: "correct horse"},
		{name: "empty credentials", username: "", password: ""},
		{name: "password of the username", username: "root", password: "root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CheckAdmin(tc.username, tc.password)
			if err != nil {
				t.Fatalf("CheckAdmin: %v", err)
			}
			if got != tc.want {
				t.Errorf("CheckAdmin(%q, %q) = %v, want %v", tc.username, tc.password, got, tc.want)
			}
		})
	}
}

func TestSetAdminReplacesUsernameAndPassword(t *testing.T) {
	s, _ := openTestStore(t)

	if err := s.SetAdmin("root", "first pass"); err != nil {
		t.Fatalf("first SetAdmin: %v", err)
	}
	if err := s.SetAdmin("operator", "second pass"); err != nil {
		t.Fatalf("second SetAdmin: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{name: "new credentials", username: "operator", password: "second pass", want: true},
		{name: "old username with the new password", username: "root", password: "second pass"},
		{name: "old credentials", username: "root", password: "first pass"},
		{name: "new username with the old password", username: "operator", password: "first pass"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CheckAdmin(tc.username, tc.password)
			if err != nil {
				t.Fatalf("CheckAdmin: %v", err)
			}
			if got != tc.want {
				t.Errorf("CheckAdmin(%q, %q) = %v, want %v", tc.username, tc.password, got, tc.want)
			}
		})
	}

	var rows int64
	if err := s.DB().Model(&Admin{}).Count(&rows).Error; err != nil {
		t.Fatalf("count admins: %v", err)
	}
	if rows != 1 {
		t.Errorf("admin rows = %d, want exactly 1", rows)
	}
}

func TestSetAdminRejectsEmptyInput(t *testing.T) {
	s, _ := openTestStore(t)

	tests := []struct {
		name     string
		username string
		password string
		want     error
	}{
		{name: "empty username", username: "", password: "pass", want: ErrEmptyUsername},
		{name: "blank username", username: "   ", password: "pass", want: ErrEmptyUsername},
		{name: "empty password", username: "root", password: "", want: ErrEmptyPassword},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.SetAdmin(tc.username, tc.password)
			if !errors.Is(err, tc.want) {
				t.Errorf("SetAdmin = %v, want %v", err, tc.want)
			}
		})
	}
	if _, ok, err := s.Admin(); err != nil || ok {
		t.Errorf("a rejected SetAdmin wrote a row: ok=%v err=%v", ok, err)
	}
}

func TestSetAdminTrimsTheUsername(t *testing.T) {
	s, _ := openTestStore(t)

	if err := s.SetAdmin("  root  ", "pass"); err != nil {
		t.Fatalf("SetAdmin: %v", err)
	}
	row, _, err := s.Admin()
	if err != nil {
		t.Fatalf("Admin: %v", err)
	}
	if row.Username != "root" {
		t.Errorf("username = %q, want %q", row.Username, "root")
	}
	if ok, err := s.CheckAdmin("root", "pass"); err != nil || !ok {
		t.Errorf("CheckAdmin after trimming = %v, %v, want true, nil", ok, err)
	}
}
