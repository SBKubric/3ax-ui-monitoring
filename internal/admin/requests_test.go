package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// register puts one pending registration request in the registry, as POST
// /v1/register would. Each caller passes its own IP because spec §6 rate
// limits one request per IP per minute.
func (h *harness) register(code, hostname, ip string) string {
	h.t.Helper()
	out, err := h.reg.Register(context.Background(), registry.RegisterInput{
		PairingCode: code,
		Hostname:    hostname,
		Version:     "0.1.0",
		PublicIP:    ip,
		RemoteIP:    ip,
	})
	if err != nil {
		h.t.Fatalf("Register: %v", err)
	}
	return out.RequestID
}

// TestRequests_List shows the page's whole payload: the pending rows, the
// replacement hint of spec §6, the rate limits in the header and the
// server's clock for the countdown.
func TestRequests_List(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.register("7K3F9Q", "vps-ams-2", "203.0.113.5")

	w := h.do(http.MethodGet, "/admin/api/requests", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	o := obj(t, w)

	pending, _ := o["pending"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	row := pending[0].(map[string]any)
	if row["requestId"] != id || row["pairingCode"] != "7K3F9Q" || row["hostname"] != "vps-ams-2" {
		t.Fatalf("row = %+v", row)
	}
	if row["suggestReplacement"] != nil {
		t.Fatalf("a brand-new hostname suggested a replacement: %+v", row["suggestReplacement"])
	}
	if row["attempt"].(float64) != 1 {
		t.Fatalf("attempt = %v, want 1", row["attempt"])
	}

	limits := o["limits"].(map[string]any)
	if limits["perIpPerMin"].(float64) != 1 || limits["pendingPerIp"].(float64) != 3 || limits["pendingGlobal"].(float64) != 20 {
		t.Fatalf("limits = %+v, want spec §6's 1/3/20", limits)
	}
	if o["now"] == nil {
		t.Fatal("no server clock in the payload")
	}
}

// TestRequests_ApproveNew is the issue's "Approve ... через API меняет
// реестр как в шаге 4": a pending request becomes a mon-client whose id is
// the slug of the name, with a token parked for its next poll.
func TestRequests_ApproveNew(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.register("7K3F9Q", "vps-ams-2", "203.0.113.5")

	w := h.do(http.MethodPost, "/admin/api/requests/"+id+"/approve", map[string]any{
		"mode": "new", "name": "Amsterdam #2", "region": "NL", "paths": []string{"proxy", "direct"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if got := obj(t, w)["monClientId"]; got != "amsterdam-2" {
		t.Fatalf("monClientId = %v, want amsterdam-2", got)
	}

	clients, err := h.reg.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("registry holds %d mon-clients, want 1", len(clients))
	}
	mc := clients[0]
	if mc.Id != "amsterdam-2" || mc.Name != "Amsterdam #2" || mc.Region != "NL" || !mc.Enabled || mc.State != store.MonClientNever {
		t.Fatalf("mon-client = %+v", mc)
	}
	if mc.TokenHash == "" {
		t.Fatal("approved mon-client has no token hash")
	}

	// The request is gone from the page and carries the plaintext token
	// until the box collects it (spec §6).
	if o := obj(t, h.do(http.MethodGet, "/admin/api/requests", nil)); len(o["pending"].([]any)) != 0 {
		t.Fatal("an approved request is still listed as pending")
	}
	var req store.RegistrationRequest
	if err := h.st.DB.First(&req, "request_id = ?", id).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if req.Status != store.RegistrationApproved || req.ApprovedToken == "" || req.MonClientId != "amsterdam-2" {
		t.Fatalf("request after approval = %+v", req)
	}
}

// TestRequests_ApproveAsReplacement: the same box registering again keeps
// its id, name, region, paths and history; only the token changes (spec §6).
func TestRequests_ApproveAsReplacement(t *testing.T) {
	h := newHarness(t)
	h.login()

	first := h.register("7K3F9Q", "msk-1", "198.51.100.7")
	if w := h.do(http.MethodPost, "/admin/api/requests/"+first+"/approve", map[string]any{
		"mode": "new", "name": "Moscow #1", "region": "RU", "paths": []string{"proxy"},
	}); w.Code != http.StatusOK {
		t.Fatalf("first approve: %s", w.Body.String())
	}
	before, err := h.reg.Get(context.Background(), "moscow-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// The same box comes back after a revoke or a reinstall.
	h.clk.Advance(2 * 60 * 1e9) // two minutes: past the per-IP rate limit
	second := h.register("Q2V8NM", "msk-1", "198.51.100.7")

	// The page offers the replacement (spec §6's "подсказка").
	o := obj(t, h.do(http.MethodGet, "/admin/api/requests", nil))
	row := o["pending"].([]any)[0].(map[string]any)
	suggest, _ := row["suggestReplacement"].(map[string]any)
	if suggest == nil || suggest["monClientId"] != "moscow-1" {
		t.Fatalf("suggestReplacement = %+v, want moscow-1", row["suggestReplacement"])
	}

	w := h.do(http.MethodPost, "/admin/api/requests/"+second+"/approve", map[string]any{
		"mode": "replace", "existingId": "moscow-1",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("replacement approve: status %d, body %s", w.Code, w.Body.String())
	}

	clients, _ := h.reg.List(context.Background())
	if len(clients) != 1 {
		t.Fatalf("registry holds %d mon-clients after a replacement, want 1", len(clients))
	}
	after := clients[0]
	if after.Id != before.Id || after.Name != before.Name || after.Region != before.Region || after.Paths != before.Paths {
		t.Fatalf("replacement changed the record: before %+v, after %+v", before, after)
	}
	if after.TokenHash == before.TokenHash || after.TokenHash == "" {
		t.Fatalf("replacement did not rotate the token (before %q, after %q)", before.TokenHash, after.TokenHash)
	}
	if after.State != store.MonClientNever {
		t.Fatalf("state = %q, want NEVER until the first heartbeat", after.State)
	}
}

// TestRequests_ApproveReplacementNeedsAnExistingId: the mode is the
// administrator's explicit choice, so "replace" without a target is a
// client error, not a silent new mon-client.
func TestRequests_ApproveReplacementNeedsAnExistingId(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.register("7K3F9Q", "vps-ams-2", "203.0.113.5")

	w := h.do(http.MethodPost, "/admin/api/requests/"+id+"/approve", map[string]any{"mode": "replace"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if clients, _ := h.reg.List(context.Background()); len(clients) != 0 {
		t.Fatalf("a mon-client was created anyway: %+v", clients)
	}
}

// TestRequests_Reject records the refusal and takes the row off the page.
func TestRequests_Reject(t *testing.T) {
	h := newHarness(t)
	h.login()
	id := h.register("7K3F9Q", "vps-ams-2", "203.0.113.5")

	if w := h.do(http.MethodPost, "/admin/api/requests/"+id+"/reject", nil); w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	var req store.RegistrationRequest
	if err := h.st.DB.First(&req, "request_id = ?", id).Error; err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if req.Status != store.RegistrationRejected {
		t.Fatalf("status = %q, want rejected", req.Status)
	}
	if clients, _ := h.reg.List(context.Background()); len(clients) != 0 {
		t.Fatal("rejecting created a mon-client")
	}
	if o := obj(t, h.do(http.MethodGet, "/admin/api/requests", nil)); len(o["pending"].([]any)) != 0 {
		t.Fatal("a rejected request is still listed as pending")
	}
}

// TestRequests_ApproveUnknownRequest: acting on a request that expired or
// was already handled is a clean 404/409, never a 500.
func TestRequests_ApproveUnknownRequest(t *testing.T) {
	h := newHarness(t)
	h.login()

	w := h.do(http.MethodPost, "/admin/api/requests/nosuchrequest/approve", map[string]any{"mode": "new", "name": "X"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", w.Code)
	}
	if env := decode(t, w); env.Success || env.Msg == "" {
		t.Fatalf("envelope = %+v, want success:false with a message", env)
	}
}
