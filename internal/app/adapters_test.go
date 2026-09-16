package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/admin"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
)

// TestAdminErrorTranslation: the registry and the admin UI have separate error
// vocabularies on purpose, and this is the only place that knows both. Without
// the translation every registry refusal reaches the browser as an internal
// error, so approving a request someone else just handled would look like a
// broken server instead of a stale page.
func TestAdminErrorTranslation(t *testing.T) {
	tests := []struct {
		name string
		in   error
		want error
	}{
		{name: "no error stays nil", in: nil, want: nil},
		{name: "unknown request is not found", in: registry.ErrRequestNotFound, want: admin.ErrNotFound},
		{name: "unknown mon-client is not found", in: registry.ErrMonClientNotFound, want: admin.ErrNotFound},
		{name: "expired request is a conflict", in: registry.ErrRequestExpired, want: admin.ErrConflict},
		{name: "already handled request is a conflict", in: registry.ErrRequestNotPending, want: admin.ErrConflict},
		{name: "no free id is a conflict", in: registry.ErrNoFreeID, want: admin.ErrConflict},
		{name: "empty name is invalid", in: registry.ErrEmptyName, want: admin.ErrInvalid},
		{name: "bad paths are invalid", in: registry.ErrInvalidPaths, want: admin.ErrInvalid},
		{name: "wrapped errors are still recognised", in: fmt.Errorf("approve: %w", registry.ErrMonClientNotFound), want: admin.ErrNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := adminError(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("adminError(%v) = %v, want nil", tc.in, got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("adminError(%v) = %v, want it to be %v", tc.in, got, tc.want)
			}
			if got.Error() == tc.want.Error() {
				t.Error("the translation dropped the original reason, which the log needs")
			}
		})
	}
}

// TestAdminErrorKeepsAnythingElseIntact: a storage failure must not be dressed
// up as a client mistake, or a broken database would answer 400 and nobody
// would look at the logs.
func TestAdminErrorKeepsAnythingElseIntact(t *testing.T) {
	boom := errors.New("database is locked")
	got := adminError(boom)
	if !errors.Is(got, boom) {
		t.Fatalf("adminError(%v) = %v, want the original error", boom, got)
	}
	for _, sentinel := range []error{admin.ErrNotFound, admin.ErrConflict, admin.ErrInvalid} {
		if errors.Is(got, sentinel) {
			t.Errorf("an unrecognised failure was translated to %v", sentinel)
		}
	}
}

// TestProbeConfigsMapping pins the poll seam: the material arrives keyed by
// path, and a path the panel did not serve must stay absent rather than
// becoming an empty set, which would look like "this panel has no inbounds".
func TestProbeConfigsMapping(t *testing.T) {
	both := probeConfigs(map[string]panel.ProbeConfigs{
		panel.PathProxy:  {Revision: "aaaa", Path: panel.PathProxy},
		panel.PathDirect: {Revision: "aaaa", Path: panel.PathDirect},
	})
	if both.Proxy == nil || both.Direct == nil {
		t.Fatalf("both paths should be present, got %+v", both)
	}
	if both.Proxy.Path != panel.PathProxy || both.Direct.Path != panel.PathDirect {
		t.Errorf("the two paths were swapped: %+v", both)
	}

	// The override being off is exactly this case, and it must not be confused
	// with an empty proxy set.
	directOnly := probeConfigs(map[string]panel.ProbeConfigs{
		panel.PathDirect: {Revision: "bbbb", Path: panel.PathDirect},
	})
	if directOnly.Proxy != nil {
		t.Error("a path the panel did not serve became an empty set")
	}
	if directOnly.Direct == nil {
		t.Error("the direct material was lost")
	}

	if empty := probeConfigs(nil); empty.Proxy != nil || empty.Direct != nil {
		t.Errorf("no material should stay no material, got %+v", empty)
	}
}
