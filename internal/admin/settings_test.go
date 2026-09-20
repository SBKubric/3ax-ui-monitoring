package admin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// settingsBody reads the Settings page's GET payload into the same shape the
// POST takes, so a test can round-trip it with one field changed — exactly
// what the page itself does.
func (h *harness) settingsBody() map[string]any {
	h.t.Helper()
	w := h.do(http.MethodGet, "/admin/api/settings", nil)
	if w.Code != http.StatusOK {
		h.t.Fatalf("GET settings: status %d, body %s", w.Code, w.Body.String())
	}
	var wrapper struct {
		Obj struct {
			Settings map[string]any `json:"settings"`
		} `json:"obj"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &wrapper); err != nil {
		h.t.Fatalf("decode settings: %v", err)
	}
	return wrapper.Obj.Settings
}

// TestSettings_Get answers with every tab spec §9.4 names: the editable
// settings, the panel status line, the read-only proxy front and the
// bootstrap block.
func TestSettings_Get(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()

	o := obj(t, h.do(http.MethodGet, "/admin/api/settings", nil))

	set := o["settings"].(map[string]any)
	if set["downAfter"].(float64) != 3 || set["intervalMs"].(float64) != 60000 {
		t.Fatalf("defaults missing from the settings payload: %+v", set)
	}

	p := o["panel"].(map[string]any)
	if p["revision"] != "c4f1a9e2" || p["polled"] != true || p["reachable"] != true {
		t.Fatalf("panel status = %+v", p)
	}
	ov := p["override"].(map[string]any)
	if ov["enabled"] != true || ov["host"] != "front.example.net" {
		t.Fatalf("override = %+v, want the panel's last reported front", ov)
	}

	b := o["bootstrap"].(map[string]any)
	if b["listen"] != ":443" || b["publicIp"] != "192.0.2.44" || b["tlsMode"] != "acme-ip" {
		t.Fatalf("bootstrap = %+v", b)
	}
	if b["adminCommand"] != adminCommandHint {
		t.Fatalf("adminCommand = %v, want %q", b["adminCommand"], adminCommandHint)
	}
}

// TestSettings_SaveRejectsNegativeNumbers: a negative threshold or timeout
// would be handed to every mon-client in its config, so it never reaches the
// settings table.
func TestSettings_SaveRejectsNegativeNumbers(t *testing.T) {
	h := newHarness(t)
	h.login()

	body := h.settingsBody()
	body["downAfter"] = -1
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if env := decode(t, w); !strings.Contains(env.Msg, "downAfter") {
		t.Fatalf("msg = %q, want it to name the field", env.Msg)
	}

	set, _ := h.st.LoadSettings()
	if set.DownAfter != 3 {
		t.Fatalf("downAfter was saved anyway: %d", set.DownAfter)
	}
}

// TestSettings_SaveProbeRebuildsEveryConfig is the issue's "Save с новыми
// probe-параметрами меняет config revision у всех mon-clients" (spec §9.4).
func TestSettings_SaveProbeRebuildsEveryConfig(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()

	one := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"proxy", "direct"})
	h.clk.Advance(2 * 60 * 1e9)
	two := h.approveOne("Q2V8NM", "vps-fra-1", "198.51.100.23", "Frankfurt #1", "DE", []string{"proxy"})

	ctx := context.Background()
	before := map[string]string{}
	for _, id := range []string{one, two} {
		rev, err := h.configs.CurrentRevision(ctx, id)
		if err != nil || rev == "" {
			t.Fatalf("no config revision for %s before the save (%v)", id, err)
		}
		before[id] = rev
	}

	body := h.settingsBody()
	body["intervalMs"] = 30000
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if obj(t, w)["rebuilt"] != true {
		t.Fatalf("rebuilt = %v, want true after a probe parameter changed", obj(t, w)["rebuilt"])
	}

	for _, id := range []string{one, two} {
		after, _ := h.configs.CurrentRevision(ctx, id)
		if after == before[id] {
			t.Fatalf("%s kept config revision %q after the probe interval changed", id, after)
		}
	}

	set, _ := h.st.LoadSettings()
	if set.IntervalMs != 30000 {
		t.Fatalf("intervalMs = %d, want the saved 30000", set.IntervalMs)
	}
}

// TestSettings_SaveRealHostRebuilds: the other trigger spec §9.4 names.
// The assertion is that the rebuild ran, not that the revision moved: a
// realHost change reaches a document through the direct probe items the
// panel hands back for the new host, and this test's material is fixed.
func TestSettings_SaveRealHostRebuilds(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"direct"})

	body := h.settingsBody()
	body["realHost"] = "real.example.net"
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %s", w.Body.String())
	}
	if obj(t, w)["rebuilt"] != true {
		t.Fatalf("rebuilt = %v, want true after realHost changed", obj(t, w)["rebuilt"])
	}
	set, _ := h.st.LoadSettings()
	if set.RealHost != "real.example.net" {
		t.Fatalf("realHost = %q, want the saved value", set.RealHost)
	}
}

// TestSettings_SaveWithoutProbeChangeDoesNotRebuild: a Telegram token or a
// threshold never appears in a config document, so it must not make every
// mon-client re-fetch one.
func TestSettings_SaveWithoutProbeChangeDoesNotRebuild(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	id := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", nil)

	ctx := context.Background()
	before, _ := h.configs.CurrentRevision(ctx, id)

	body := h.settingsBody()
	body["tgChatId"] = "-1001234567890"
	body["downAfter"] = 5
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %s", w.Body.String())
	}
	if obj(t, w)["rebuilt"] != false {
		t.Fatalf("rebuilt = %v, want false", obj(t, w)["rebuilt"])
	}
	if after, _ := h.configs.CurrentRevision(ctx, id); after != before {
		t.Fatalf("config revision changed (%q → %q) for a setting no mon-client sees", before, after)
	}

	set, _ := h.st.LoadSettings()
	if set.TgChatID != "-1001234567890" || set.DownAfter != 5 {
		t.Fatalf("settings not saved: %+v", set)
	}
}

// TestSettings_CheckUsesSubmittedValuesAndSavesNothing is the issue's "Check
// дёргает GET /state по введённым значениям, не сохраняя" (spec §9.4).
func TestSettings_CheckUsesSubmittedValuesAndSavesNothing(t *testing.T) {
	h := newHarness(t)
	h.login()

	stub := paneltest.NewStub(t)
	stub.SetInbounds([]panel.Inbound{
		{Kind: store.InboundKindXray, InboundId: 12, Tag: "inbound-443", Protocol: "vless", Port: 443, Enable: true},
		{Kind: store.InboundKindAwg, InboundId: 0, Tag: "awg", Protocol: "awg", Port: 51820, Enable: true},
	})
	stub.SetOverride(true, "front.example.net")

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	o := obj(t, w)
	if o["revision"] != stub.Revision() {
		t.Fatalf("revision = %v, want the stub's %q", o["revision"], stub.Revision())
	}
	if o["inbounds"].(float64) != 2 {
		t.Fatalf("inbounds = %v, want 2", o["inbounds"])
	}
	ov := o["override"].(map[string]any)
	if ov["enabled"] != true || ov["host"] != "front.example.net" {
		t.Fatalf("override = %+v", ov)
	}

	// The client was built from what was typed, and nothing was saved.
	if len(h.panelClients) != 1 || h.panelClients[0] != stub.URL()+"|"+stub.Token() {
		t.Fatalf("panel clients built = %+v, want one from the submitted values", h.panelClients)
	}
	set, _ := h.st.LoadSettings()
	if set.PanelURL != "" || set.MonToken != "" {
		t.Fatalf("Check saved the settings: %+v", set)
	}
}

// TestSettings_CheckBare404 explains the panel's deliberate 404 (contract
// §2) instead of echoing a status nobody can act on.
func TestSettings_CheckBare404(t *testing.T) {
	h := newHarness(t)
	h.login()

	stub := paneltest.NewStub(t)
	stub.SetMonEnabled(false)

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(),
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", w.Code)
	}
	msg := decode(t, w).Msg
	for _, want := range []string{"404", "token", "webBasePath", "switched off"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("msg = %q, want it to mention %q", msg, want)
		}
	}
}

// TestSettings_CheckNeedsBothValues: an empty form is a client error, not a
// request to the empty URL.
func TestSettings_CheckNeedsBothValues(t *testing.T) {
	h := newHarness(t)
	h.login()

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{"panelUrl": "", "monToken": ""})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if len(h.panelClients) != 0 {
		t.Fatalf("a panel client was built for an empty form: %+v", h.panelClients)
	}
}

// TestSettings_TelegramTestUsesSubmittedToken: "Send test" reaches the Bot
// API with the token and chat typed into the form, and saves neither.
func TestSettings_TelegramTestUsesSubmittedToken(t *testing.T) {
	h := newHarness(t)
	h.login()

	var gotPath, gotBody string
	bot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer bot.Close()
	h.handler.deps.Telegram = tg.NewHTTP(bot.Client(), bot.URL)

	w := h.do(http.MethodPost, "/admin/api/settings/telegram-test", map[string]any{
		"tgToken": "7412:AAHsecret", "tgChatId": "-1001234567890",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if gotPath != "/bot7412:AAHsecret/sendMessage" {
		t.Fatalf("path = %q, want the submitted token's sendMessage", gotPath)
	}
	if !strings.Contains(gotBody, "-1001234567890") || !strings.Contains(gotBody, "mon-server") {
		t.Fatalf("body = %q", gotBody)
	}

	set, _ := h.st.LoadSettings()
	if set.TgToken != "" || set.TgChatID != "" {
		t.Fatalf("Send test saved the credentials: %+v", set)
	}
}

// TestSettings_TelegramTestReportsRefusal: Telegram's own description
// reaches the administrator, because it is the only thing that says what is
// actually wrong (wrong chat, bot not in the chat, revoked token).
func TestSettings_TelegramTestReportsRefusal(t *testing.T) {
	h := newHarness(t)
	h.login()

	bot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found"}`))
	}))
	defer bot.Close()
	h.handler.deps.Telegram = tg.NewHTTP(bot.Client(), bot.URL)

	w := h.do(http.MethodPost, "/admin/api/settings/telegram-test", map[string]any{
		"tgToken": "7412:AAHsecret", "tgChatId": "-1",
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", w.Code)
	}
	if msg := decode(t, w).Msg; !strings.Contains(msg, "chat not found") {
		t.Fatalf("msg = %q, want Telegram's own description", msg)
	}
}
