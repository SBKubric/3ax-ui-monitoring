package admin

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// sampleClients is the registry the mon-clients tests work with: one box that
// is online, one that has never been seen and one that is disabled with a
// config error.
func sampleClients() []Client {
	return []Client{
		{
			ID: "msk-1", Name: "Moscow #1", Region: "RU", Paths: []string{"proxy", "direct"},
			Enabled: true, State: "ONLINE", LastHeartbeat: clock.MS(testTime) - 30_000,
			ApprovedAt: clock.MS(testTime) - 86_400_000, Version: "0.1.0", XrayVersion: "1.8.24",
			AppliedRevision: "a1b2c3d4e5f60718", ConfigRevision: "a1b2c3d4e5f60718",
		},
		{
			ID: "ams-2", Name: "Amsterdam #2", Region: "NL", Paths: []string{"proxy"},
			Enabled: true, State: "NEVER", ApprovedAt: clock.MS(testTime) - 600_000,
		},
		{
			ID: "fra-3", Name: "Frankfurt #3", Region: "DE", Paths: []string{"direct"},
			Enabled: false, State: "OFFLINE", LastHeartbeat: clock.MS(testTime) - 7_200_000,
			AppliedRevision: "0000111122223333", ConfigRevision: "4444555566667777",
			ConfigError: "probe: cannot resolve real host\nsecond line", ConfigErrorAt: clock.MS(testTime) - 60_000,
			TokenRevoked: true,
		},
	}
}

// TestClientsListCarriesTheTable: every column of §9.3 is in the payload.
func TestClientsListCarriesTheTable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.clients = sampleClients()
	h.registry.pending = []PendingRequest{samplePending()}
	cookie := h.signIn()

	rec := h.get("/admin/api/clients", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var payload clientsPayload
	decodeObj(t, rec, &payload)

	if payload.Pending != 1 {
		t.Errorf("pending = %d, want 1 for the sidebar badge", payload.Pending)
	}
	if len(payload.Clients) != 3 {
		t.Fatalf("got %d clients, want 3", len(payload.Clients))
	}
	broken := payload.Clients[2]
	if broken.ConfigError == "" || !strings.Contains(broken.ConfigError, "second line") {
		t.Errorf("config error = %q, want the full text for the tooltip", broken.ConfigError)
	}
	if broken.AppliedRevision == broken.ConfigRevision {
		t.Error("the applied and the built revision should differ in this fixture")
	}
	if !broken.TokenRevoked {
		t.Error("the revoked token is not reported")
	}
}

// TestClientsListHasNoNullPaths keeps the table from having to guard.
func TestClientsListHasNoNullPaths(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.clients = []Client{{ID: "msk-1", Name: "Moscow #1"}}
	cookie := h.signIn()

	rec := h.get("/admin/api/clients", cookie)
	if strings.Contains(rec.Body.String(), `"paths":null`) {
		t.Errorf("body carries a null paths array: %s", rec.Body.String())
	}
}

// TestEditClientReachesTheRegistry: the Edit modal's three fields arrive, the
// id comes from the path and never changes.
func TestEditClientReachesTheRegistry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	body := map[string]any{"name": " Moscow #1 ", "region": " RU ", "paths": []string{"direct", "proxy"}}
	rec := h.post("/admin/api/clients/msk-1", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	want := []editCall{{ID: "msk-1", Edit: ClientEdit{Name: "Moscow #1", Region: "RU", Paths: []string{"proxy", "direct"}}}}
	if !reflect.DeepEqual(h.registry.edits, want) {
		t.Errorf("edits = %+v, want %+v", h.registry.edits, want)
	}
}

// TestEditClientRefusesBadInput: the same guards as approval.
func TestEditClientRefusesBadInput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{name: "empty name", path: "/admin/api/clients/msk-1", body: map[string]any{"name": " ", "paths": []string{"proxy"}}},
		{name: "unknown path", path: "/admin/api/clients/msk-1", body: map[string]any{"name": "Moscow", "paths": []string{"sideways"}}},
		{name: "no paths", path: "/admin/api/clients/msk-1", body: map[string]any{"name": "Moscow", "paths": []string{}}},
		{name: "impossible id", path: "/admin/api/clients/not%20a%20slug", body: map[string]any{"name": "Moscow", "paths": []string{"proxy"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			cookie := h.signIn()

			rec := h.post(c.path, c.body, cookie)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if len(h.registry.edits) != 0 {
				t.Errorf("the registry was called with %+v", h.registry.edits)
			}
		})
	}
}

// TestEnabledSwitch covers both directions of the switch.
func TestEnabledSwitch(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	if rec := h.post("/admin/api/clients/msk-1/enabled", map[string]any{"enabled": false}, cookie); rec.Code != http.StatusOK {
		t.Fatalf("disable: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := h.post("/admin/api/clients/msk-1/enabled", map[string]any{"enabled": true}, cookie); rec.Code != http.StatusOK {
		t.Fatalf("enable: status = %d (%s)", rec.Code, rec.Body.String())
	}
	want := []switchCall{{ID: "msk-1", Enabled: false}, {ID: "msk-1", Enabled: true}}
	if !reflect.DeepEqual(h.registry.switches, want) {
		t.Errorf("switches = %+v, want %+v", h.registry.switches, want)
	}
}

// TestEnabledSwitchNeedsAValue: an absent flag is not "false".
func TestEnabledSwitchNeedsAValue(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post("/admin/api/clients/msk-1/enabled", map[string]any{}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(h.registry.switches) != 0 {
		t.Errorf("the registry was switched with %+v", h.registry.switches)
	}
}

// TestRevokeAndDeleteReachTheRegistry.
func TestRevokeAndDeleteReachTheRegistry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post("/admin/api/clients/msk-1/revoke", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if env := decode(t, rec); !strings.Contains(env.Msg, "replacement") {
		t.Errorf("revoke msg = %q, want it to explain the replacement", env.Msg)
	}
	if !reflect.DeepEqual(h.registry.revokes, []string{"msk-1"}) {
		t.Errorf("revokes = %v, want [msk-1]", h.registry.revokes)
	}

	if rec := h.post("/admin/api/clients/fra-3/delete", nil, cookie); rec.Code != http.StatusOK {
		t.Fatalf("delete: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !reflect.DeepEqual(h.registry.deletes, []string{"fra-3"}) {
		t.Errorf("deletes = %v, want [fra-3]", h.registry.deletes)
	}
}

// TestClientOperationsRefuseAnImpossibleID keeps a path parameter from
// reaching the registry unchecked.
func TestClientOperationsRefuseAnImpossibleID(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	for _, path := range []string{
		"/admin/api/clients/no%20slug/revoke",
		"/admin/api/clients/no%20slug/delete",
		"/admin/api/clients/no%20slug/enabled",
	} {
		rec := h.post(path, map[string]any{"enabled": true}, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
	}
	if len(h.registry.revokes)+len(h.registry.deletes)+len(h.registry.switches) != 0 {
		t.Error("an impossible id reached the registry")
	}
}
