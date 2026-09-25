package admin

import (
	"context"
	"encoding/json"
	"errors"
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

	one := h.approveOne("7K3F9Q", "vps-ams-2", "203.0.113.5", "Amsterdam #2", "NL", []string{"hops", "direct"})
	h.clk.Advance(2 * 60 * 1e9)
	two := h.approveOne("Q2V8NM", "vps-fra-1", "198.51.100.23", "Frankfurt #1", "DE", []string{"hops"})

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
// The assertion is that the rebuild ran (through the poller's material
// refresh, decision #51 §4), not that the revision moved: a realHost change
// reaches a document through the direct probe items the panel hands back
// for the new host, and this test's material is fixed.
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

// TestSettings_PanelCASaveValidatesPEM checks decision #52 §1's Save side:
// panelCa is a PEM chain that replaces the system pool for panel requests,
// so a value that does not parse as certificates is refused with a message
// naming the field, and nothing is saved; a real certificate round-trips.
func TestSettings_PanelCASaveValidatesPEM(t *testing.T) {
	h := newHarness(t)
	h.login()

	body := h.settingsBody()
	body["panelCa"] = "not a certificate"
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400; body %s", w.Code, w.Body.String())
	}
	if msg := decode(t, w).Msg; !strings.Contains(msg, "panelCa") {
		t.Fatalf("msg = %q, want it to name panelCa", msg)
	}
	if set, _ := h.st.LoadSettings(); set.PanelCA != "" {
		t.Fatalf("a broken panelCa was saved: %q", set.PanelCA)
	}

	pem := paneltest.NewTLSStub(t).CertPEM()
	body["panelCa"] = pem
	if w := h.do(http.MethodPost, "/admin/api/settings", body); w.Code != http.StatusOK {
		t.Fatalf("save with a valid panelCa: status %d, body %s", w.Code, w.Body.String())
	}
	if got := h.settingsBody()["panelCa"]; got != strings.TrimSpace(pem) {
		t.Fatalf("panelCa after save = %q, want the certificate", got)
	}
}

// TestSettings_CheckUnknownAuthority checks the Check button's own text for
// a panel whose certificate the current trust (here: the system pool) does
// not cover — decision #52 §1 — so an operator is pointed at panelCa rather
// than told the panel "did not answer".
func TestSettings_CheckUnknownAuthority(t *testing.T) {
	h := newHarness(t)
	h.login()
	stub := paneltest.NewTLSStub(t)

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(),
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502; body %s", w.Code, w.Body.String())
	}
	msg := decode(t, w).Msg
	for _, want := range []string{"unknown authority", "Panel CA"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("msg = %q, want it to mention %q", msg, want)
		}
	}
}

// TestSettings_CheckUsesSubmittedPanelCA checks that Check trusts the
// panelCa typed into the form (not the saved one, spec §9.4 "без Save"):
// with the panel's self-signed certificate pasted in, the same panel is
// reachable, and still nothing is saved.
func TestSettings_CheckUsesSubmittedPanelCA(t *testing.T) {
	h := newHarness(t)
	h.login()
	stub := paneltest.NewTLSStub(t)

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(), "panelCa": stub.CertPEM(),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	if set, _ := h.st.LoadSettings(); set.PanelCA != "" {
		t.Fatalf("Check saved panelCa: %q", set.PanelCA)
	}
}

// TestSettings_CheckRejectsBrokenPanelCA: a panelCa that does not parse is
// the form's error, reported before any request is made.
func TestSettings_CheckRejectsBrokenPanelCA(t *testing.T) {
	h := newHarness(t)
	h.login()

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": "https://192.0.2.10/", "monToken": "t", "panelCa": "garbage",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if msg := decode(t, w).Msg; !strings.Contains(msg, "panelCa") {
		t.Fatalf("msg = %q, want it to name panelCa", msg)
	}
	if len(h.panelClients) != 0 {
		t.Fatalf("a panel client was built for a broken panelCa: %+v", h.panelClients)
	}
}

// TestSettings_GetStatusUnknownAuthorityAndACMECA checks the two read-only
// additions of decision #52 to GET /admin/api/settings: the status line
// learns that the poller's last failure was an untrusted panel certificate,
// and the "TLS & admin" block shows which ACME CA the bootstrap config
// chose, both as named and as the directory URL it resolves to.
func TestSettings_GetStatusUnknownAuthorityAndACMECA(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.mat.untrusted = true
	h.handler.deps.Cfg.TLS.ACMECA = "staging"

	o := obj(t, h.do(http.MethodGet, "/admin/api/settings", nil))
	if p := o["panel"].(map[string]any); p["unknownAuthority"] != true {
		t.Fatalf("panel status = %+v, want unknownAuthority true", p)
	}
	b := o["bootstrap"].(map[string]any)
	if b["acmeCa"] != "staging" || b["acmeDirectory"] != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Fatalf("bootstrap = %+v, want acmeCa staging and its directory", b)
	}
}

// TestSettings_SavePanelAddressRefreshesMaterial is decision #51 §4: the
// direct links are rendered for realHost (by default the host of
// panelUrl), and neither moves the panel's revision, so a Save that changes
// either makes the poller drop its cached material, re-read
// /probe/configs and rebuild every config — right away, not whenever the
// panel's revision next happens to move.
func TestSettings_SavePanelAddressRefreshesMaterial(t *testing.T) {
	for _, field := range []string{"realHost", "panelUrl"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			h.login()
			h.withMaterial()

			body := h.settingsBody()
			body[field] = "https://changed.example.net/panel/"
			if field == "realHost" {
				body[field] = "changed.example.net"
			}
			w := h.do(http.MethodPost, "/admin/api/settings", body)
			if w.Code != http.StatusOK {
				t.Fatalf("save: %s", w.Body.String())
			}
			if h.mat.refreshes != 1 {
				t.Fatalf("RefreshMaterial called %d times, want 1", h.mat.refreshes)
			}
			if obj(t, w)["rebuilt"] != true {
				t.Fatalf("rebuilt = %v, want true", obj(t, w)["rebuilt"])
			}
		})
	}
}

// TestSettings_SaveOtherFieldsDoNotRefreshMaterial: only the panel address
// reaches the probe material.
func TestSettings_SaveOtherFieldsDoNotRefreshMaterial(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()

	body := h.settingsBody()
	body["intervalMs"] = 30000
	body["tgChatId"] = "-100"
	if w := h.do(http.MethodPost, "/admin/api/settings", body); w.Code != http.StatusOK {
		t.Fatalf("save: %s", w.Body.String())
	}
	if h.mat.refreshes != 0 {
		t.Fatalf("RefreshMaterial called %d times, want 0", h.mat.refreshes)
	}
}

// TestSettings_SaveRefreshFailureStillSaves: an unreachable panel does not
// fail the Save — the settings are right, and the poller finishes the
// refresh on its next cycle — but the answer says the configs were not
// rebuilt yet.
func TestSettings_SaveRefreshFailureStillSaves(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()
	h.mat.refreshErr = errors.New("panel: connection refused")

	body := h.settingsBody()
	body["realHost"] = "changed.example.net"
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %s", w.Body.String())
	}
	if obj(t, w)["rebuilt"] != false {
		t.Fatalf("rebuilt = %v, want false", obj(t, w)["rebuilt"])
	}
	if msg := decode(t, w).Msg; !strings.Contains(msg, "next panel poll") {
		t.Fatalf("msg = %q, want it to say the next poll retries", msg)
	}
	if set, _ := h.st.LoadSettings(); set.RealHost != "changed.example.net" {
		t.Fatalf("realHost = %q, want it saved anyway", set.RealHost)
	}
}

// TestSettings_CheckReadsProbeConfigsForTypedRealHost is Check's half of
// decision #51 §4: with the typed panel address it also asks for the probe
// material — the direct path for the typed realHost, the proxy path when the
// override is on — and reports how many links came back, still saving and
// refreshing nothing.
func TestSettings_CheckReadsProbeConfigsForTypedRealHost(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withMaterial()

	stub := paneltest.NewStub(t)
	sub := "sub-1"
	stub.SetProbeSubID(&sub)
	stub.SetInbounds([]panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Protocol: "vless", Port: 443, Enable: true}})
	stub.SetOverride(true, "front.example.net")
	stub.SetItems("direct", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct"}})
	stub.SetItems("proxy", []panel.ProbeItem{
		{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://proxy"},
		{Kind: store.InboundKindAwg, InboundId: 0, Conf: "[Peer]"},
	})

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(), "realHost": "typed.example.net",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	o := obj(t, w)
	if o["realHost"] != "typed.example.net" {
		t.Fatalf("realHost = %v, want the typed one", o["realHost"])
	}
	items, _ := o["probeItems"].(map[string]any)
	if items["direct"] != float64(1) || items["proxy"] != float64(2) {
		t.Fatalf("probeItems = %+v, want direct 1, proxy 2", o["probeItems"])
	}
	var hosts []string
	for _, r := range stub.Requests() {
		if strings.HasSuffix(r.Path, "/probe/configs") {
			hosts = append(hosts, r.Query.Get("host"))
		}
	}
	if len(hosts) != 2 || hosts[0] != "typed.example.net" || hosts[1] != "" {
		t.Fatalf("probe/configs hosts = %q, want the typed realHost, then the proxy path", hosts)
	}
	if h.mat.refreshes != 0 {
		t.Fatalf("Check refreshed the poller's material (%d)", h.mat.refreshes)
	}
	if set, _ := h.st.LoadSettings(); set.RealHost != "" || set.PanelURL != "" {
		t.Fatalf("Check saved the settings: %+v", set)
	}
}

// TestSettings_CheckProbeConfigsFailureIsReported: the panel answering
// /state but refusing /probe/configs (a probe set never ensured) is still
// "reachable", with the refusal named.
func TestSettings_CheckProbeConfigsFailureIsReported(t *testing.T) {
	h := newHarness(t)
	h.login()

	stub := paneltest.NewStub(t)
	stub.SetInbounds([]panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Protocol: "vless", Port: 443, Enable: true}})

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	o := obj(t, w)
	if msg, _ := o["probeError"].(string); !strings.Contains(msg, "probe_not_ensured") {
		t.Fatalf("probeError = %v, want the panel's refusal", o["probeError"])
	}
	if o["realHost"] != "127.0.0.1" {
		t.Fatalf("realHost = %v, want the panel URL's host by default", o["realHost"])
	}
}

// TestSettings_SaveRealHostWithoutPanelIsJustSaved: before the panel is
// configured there is no material to refresh, and Save says "Saved." rather
// than claiming a rebuild or a failure.
func TestSettings_SaveRealHostWithoutPanelIsJustSaved(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.mat.refreshErr = panel.ErrPanelNotConfigured

	body := h.settingsBody()
	body["realHost"] = "changed.example.net"
	w := h.do(http.MethodPost, "/admin/api/settings", body)
	if w.Code != http.StatusOK {
		t.Fatalf("save: %s", w.Body.String())
	}
	if obj(t, w)["rebuilt"] != false || decode(t, w).Msg != "Saved." {
		t.Fatalf("answer = %s, want a plain \"Saved.\" with rebuilt=false", w.Body.String())
	}
}

// TestSettings_CheckRefusesContractMismatch is decisions #80 п. 9 and #61
// п. 5: a panel on any other monitoring contract answers, but mon-server
// would build no targets from it, so Check fails with the text that names
// both versions and the side to update — and asks for no probe configs.
func TestSettings_CheckRefusesContractMismatch(t *testing.T) {
	for contract, want := range map[int]string{
		2: "panel speaks monitoring contract 2, mon-server needs 3 — update the panel",
		4: "panel speaks monitoring contract 4, mon-server needs 3 — update mon-server",
	} {
		h := newHarness(t)
		h.login()

		stub := paneltest.NewStub(t)
		stub.SetContract(contract)

		w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
			"panelUrl": stub.URL(), "monToken": stub.Token(),
		})
		if w.Code != http.StatusBadGateway {
			t.Fatalf("contract %d: status %d, want 502", contract, w.Code)
		}
		if msg := decode(t, w).Msg; msg != want {
			t.Fatalf("msg = %q, want %q", msg, want)
		}
		for _, r := range stub.Requests() {
			if strings.HasSuffix(r.Path, "/probe/configs") {
				t.Fatalf("Check read probe configs from a contract-%d panel: %s", contract, r.Path)
			}
		}
	}
}

// TestSettings_GetStatusContractError: the status line carries the poller's
// contract refusal, since the panel is reachable and nothing else on the
// page would say why no mon-client gets targets.
func TestSettings_GetStatusContractError(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.mat.contract = "panel speaks monitoring contract 2, mon-server needs 3 — update the panel"

	o := obj(t, h.do(http.MethodGet, "/admin/api/settings", nil))
	if p := o["panel"].(map[string]any); p["contractError"] != h.mat.contract {
		t.Fatalf("panel status = %+v, want contractError %q", p, h.mat.contract)
	}
}

// TestSettings_CheckReadsEveryProbedHop is Check on a chained panel (spec
// §9.4): besides direct it reads every probed hop by ?hop= and counts the
// links per path, and never asks for proxy, which such a panel does not
// serve.
func TestSettings_CheckReadsEveryProbedHop(t *testing.T) {
	h := newHarness(t)
	h.login()

	stub := paneltest.NewStub(t)
	sub := "sub-1"
	stub.SetProbeSubID(&sub)
	stub.SetOverride(true, "a.example.net")
	stub.SetChain("edge-a", []paneltest.Hop{
		{Name: "core-1", Role: "inner", Host: "10.0.0.7", State: "joined"},
		{Name: "edge-a", Role: "edge", Host: "a.example.net", State: "joined"},
		{Name: "edge-x", Role: "edge", Host: "x.example.net", State: "pending"},
	})
	stub.SetItems("direct", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://direct"}})
	stub.SetItems("inner:core-1", []panel.ProbeItem{{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://core"}})
	stub.SetItems("edge:edge-a", []panel.ProbeItem{
		{Kind: store.InboundKindXray, InboundId: 12, Link: "vless://a"},
		paneltest.AwgItem("ams-1", "[Peer]"),
	})

	w := h.do(http.MethodPost, "/admin/api/settings/check", map[string]any{
		"panelUrl": stub.URL(), "monToken": stub.Token(), "realHost": "real.example.net",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	o := obj(t, w)
	items := o["probeItems"].(map[string]any)
	if items["direct"] != float64(1) || items["inner:core-1"] != float64(1) || items["edge:edge-a"] != float64(2) || len(items) != 3 {
		t.Fatalf("probeItems = %+v, want direct 1, inner:core-1 1, edge:edge-a 2 and nothing else", items)
	}
	if chain := o["chain"].(map[string]any); chain["activeEdge"] != "edge-a" || len(chain["hops"].([]any)) != 2 {
		t.Fatalf("chain = %+v, want the two probed hops with edge-a active", chain)
	}
	for _, r := range stub.Requests() {
		if strings.HasSuffix(r.Path, "/probe/configs") && r.Query.Get("host") == "" && r.Query.Get("hop") == "" {
			t.Fatal("Check asked a chained panel for the proxy path")
		}
	}
}

// TestSettings_GetStatusChain: the status line and the read-only proxy
// front block get the chain of the last material (spec §9.4).
func TestSettings_GetStatusChain(t *testing.T) {
	h := newHarness(t)
	h.login()
	h.withChain()

	o := obj(t, h.do(http.MethodGet, "/admin/api/settings", nil))
	chain := o["panel"].(map[string]any)["chain"].(map[string]any)
	if chain["chained"] != true || chain["activeEdge"] != "edge-a" || len(chain["hops"].([]any)) != 3 {
		t.Fatalf("panel.chain = %+v", chain)
	}
}
