package version

import "testing"

// TestVersion_DefaultsToDev checks the unstamped default, which is what
// every build that skips the Makefile's -ldflags (a plain `go build ./...`,
// including CI's) reports.
func TestVersion_DefaultsToDev(t *testing.T) {
	if got := Version(); got != "dev" {
		t.Fatalf("Version() = %q, want %q", got, "dev")
	}
}
