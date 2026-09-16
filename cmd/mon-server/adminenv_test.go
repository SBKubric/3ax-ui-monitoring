package main

import (
	"strings"
	"testing"
)

// The container image and the e2e compose have no terminal to prompt on, so
// `admin set` takes the password from MON_ADMIN_PASSWORD when it is present.
// These tests pin that path, including that it never falls back to reading
// stdin and never leaks the password into the output.

func TestAdminSetTakesThePasswordFromTheEnvironment(t *testing.T) {
	configPath, dataDir := writeConfig(t)
	t.Setenv(envAdminPassword, "from-the-environment")

	// Deliberately no input: nothing may be read from stdin on this path.
	code, stdout, stderr := call(t, "", "admin", "set", "root", "-config", configPath)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr %q)", code, exitOK, stderr)
	}
	if strings.Contains(stderr, "Password for") || strings.Contains(stderr, "Repeat password") {
		t.Errorf("prompted although the environment supplied the password: %q", stderr)
	}
	if strings.Contains(stdout, "from-the-environment") || strings.Contains(stderr, "from-the-environment") {
		t.Error("the password was echoed into the command output")
	}

	s := openStore(t, dataDir)
	ok, err := s.CheckAdmin("root", "from-the-environment")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Error("the stored administrator does not accept the password from the environment")
	}
}

func TestAdminSetFromTheEnvironmentIsIdempotent(t *testing.T) {
	configPath, dataDir := writeConfig(t)
	t.Setenv(envAdminPassword, "same-every-boot")

	for i := range 2 {
		if code, _, stderr := call(t, "", "admin", "set", "admin", "-config", configPath); code != exitOK {
			t.Fatalf("run %d: exit code = %d (stderr %q)", i, code, stderr)
		}
	}

	s := openStore(t, dataDir)
	ok, err := s.CheckAdmin("admin", "same-every-boot")
	if err != nil {
		t.Fatalf("CheckAdmin: %v", err)
	}
	if !ok {
		t.Error("a repeated seeding left the administrator unusable")
	}
}

func TestAdminSetRefusesAnEmptyEnvironmentPassword(t *testing.T) {
	configPath, dataDir := writeConfig(t)
	t.Setenv(envAdminPassword, "")

	code, _, stderr := call(t, "", "admin", "set", "root", "-config", configPath)
	if code != exitError {
		t.Fatalf("exit code = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr, envAdminPassword) {
		t.Errorf("stderr = %q, want it to name %s", stderr, envAdminPassword)
	}

	s := openStore(t, dataDir)
	if _, found, err := s.Admin(); err != nil || found {
		t.Errorf("an administrator was written despite the empty password (found %v, err %v)", found, err)
	}
}
