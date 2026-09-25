package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// withMaterial gives the config builder something to build from, so a test
// can watch config revisions change. It is the shape one panel revision
// leaves behind (spec §4), not a poll cycle.
func (h *harness) withMaterial() {
	h.t.Helper()
	h.mat.mat = panel.Material{
		Revision:   "c4f1a9e2",
		Override:   panel.Override{Enabled: true, Host: "front.example.net"},
		ProbeSubID: "sub-1",
		Proxy:      []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://proxy-1"}},
		Direct:     []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct-1"}},
	}
	h.mat.have = true
}

// approveOne registers and approves one mon-client, returning its id.
func (h *harness) approveOne(code, hostname, ip, name, region string, paths []string) string {
	h.t.Helper()
	id := h.register(code, hostname, ip)
	w := h.do(http.MethodPost, "/admin/api/requests/"+id+"/approve", map[string]any{
		"mode": "new", "name": name, "region": region, "paths": paths,
	})
	if w.Code != http.StatusOK {
		h.t.Fatalf("approve %s: %s", name, w.Body.String())
	}
	return obj(h.t, w)["monClientId"].(string)
}

// TestClients_List shows what spec §9.3's table needs — and nothing about
// target state, which the panel's Monitoring page owns.
func TestClients_List(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops", "direct"})

	w := h.do(http.MethodGet, "/admin/api/clients", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	clients := obj(t, w)["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	row := clients[0].(map[string]any)
	if row["id"] != id || row["name"] != "Amsterdam #2" || row["state"] != store.MonClientNever || row["enabled"] != true {
		t.Fatalf("row = %+v", row)
	}
	if len(row["paths"].([]any)) != 2 {
		t.Fatalf("paths = %+v, want both", row["paths"])
	}
	rev, _ := row["serverRevision"].(string)
	if rev == "" {
		t.Fatal("serverRevision is empty although the config builder has material")
	}
	for _, forbidden := range []string{"targets", "targetState"} {
		if _, bad := row[forbidden]; bad {
			t.Fatalf("the mon-clients payload carries %q; spec §9.3 says target state is never shown here", forbidden)
		}
	}
}

// TestClients_UpdateChangesPathsAndRevision: Edit keeps the id, and a paths
// change gives the mon-client a new config revision (spec §9.3, §5).
func TestClients_UpdateChangesPathsAndRevision(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops", "direct"})

	before, err := h.configs.CurrentRevision(context.Background(), id)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}

	w := h.do(http.MethodPost, "/admin/api/clients/"+id, map[string]any{
		"name": "Amsterdam #2 (moved)", "region": "NL", "paths": []string{"hops"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	mc, err := h.reg.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if mc.Id != id {
		t.Fatalf("id changed to %q", mc.Id)
	}
	if mc.Name != "Amsterdam #2 (moved)" || len(mc.PathsList()) != 1 {
		t.Fatalf("mon-client after Edit = %+v", mc)
	}

	after, _ := h.configs.CurrentRevision(context.Background(), id)
	if after == before {
		t.Fatalf("config revision unchanged (%q) after the paths changed", after)
	}
}

// TestClients_EnabledSwitch flips spec §9.3's switch both ways.
func TestClients_EnabledSwitch(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/enabled", map[string]any{"enabled": false}); w.Code != http.StatusOK {
		t.Fatalf("disable: %s", w.Body.String())
	}
	mc, _ := h.reg.Get(context.Background(), id)
	if mc.Enabled {
		t.Fatal("mon-client is still enabled after the switch was turned off")
	}

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/enabled", map[string]any{"enabled": true}); w.Code != http.StatusOK {
		t.Fatalf("enable: %s", w.Body.String())
	}
	mc, _ = h.reg.Get(context.Background(), id)
	if !mc.Enabled {
		t.Fatal("mon-client is still disabled after the switch was turned on")
	}
}

// TestClients_Revoke clears the token but keeps the row, so a later
// registration request can be approved as its replacement (spec §6).
func TestClients_Revoke(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/revoke", nil); w.Code != http.StatusOK {
		t.Fatalf("revoke: %s", w.Body.String())
	}
	mc, err := h.reg.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("the row is gone after a revoke: %v", err)
	}
	if mc.TokenHash != "" {
		t.Fatal("token hash survived the revoke")
	}
	if mc.State != store.MonClientOffline {
		t.Fatalf("state = %q, want OFFLINE", mc.State)
	}

	o := obj(t, h.do(http.MethodGet, "/admin/api/clients", nil))
	row := o["clients"].([]any)[0].(map[string]any)
	if row["tokenRevoked"] != true {
		t.Fatalf("tokenRevoked = %v, want true", row["tokenRevoked"])
	}
}

// TestClients_Delete removes the row outright (spec §6).
func TestClients_Delete(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/delete", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %s", w.Body.String())
	}
	if clients, _ := h.reg.List(context.Background()); len(clients) != 0 {
		t.Fatalf("registry still holds %+v", clients)
	}
	if w := h.do(http.MethodPost, "/admin/api/clients/"+id+"/delete", nil); w.Code != http.StatusNotFound {
		t.Fatalf("deleting twice: status %d, want 404", w.Code)
	}
}

// TestClients_ListShowsRejectedTargets: the targets a mon-client reported
// as rejected from its applied revision (protocol §5.3
// client.rejectedTargets), each with its error, are on the row the
// mon-clients page renders (spec §9.3), and a row with none has an empty
// list rather than null.
func TestClients_ListShowsRejectedTargets(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops"})

	rows := func() map[string]any {
		t.Helper()
		w := h.do(http.MethodGet, "/admin/api/clients", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d, body %s", w.Code, w.Body.String())
		}
		return obj(t, w)["clients"].([]any)[0].(map[string]any)
	}
	if got, ok := rows()["rejectedTargets"].([]any); !ok || len(got) != 0 {
		t.Fatalf("rejectedTargets = %#v, want an empty list", rows()["rejectedTargets"])
	}

	var mc store.MonClient
	mc.SetRejected([]store.RejectedTarget{{Target: "awg:3:proxy", Error: `[Interface] has an unknown key "Foo"`}})
	if err := h.st.DB.Model(&store.MonClient{}).Where("id = ?", id).Update("rejected_targets", mc.RejectedTargets).Error; err != nil {
		t.Fatalf("store rejected targets: %v", err)
	}
	got, _ := rows()["rejectedTargets"].([]any)
	if len(got) != 1 {
		t.Fatalf("rejectedTargets = %#v, want one", got)
	}
	r := got[0].(map[string]any)
	if r["target"] != "awg:3:proxy" || r["error"] != `[Interface] has an unknown key "Foo"` {
		t.Fatalf("rejected target = %+v, want the stored one", r)
	}
}
