package admin

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// storedSettings is the configuration the Settings tests start from.
func storedSettings() store.Settings {
	v := store.DefaultSettings()
	v.PanelURL = "https://panel.example.net/secretpath"
	v.MonToken = "mon-token-0123456789abcdef"
	v.RealHost = "real.example.net"
	v.TGToken = "1234567890:AAstoredtelegramtokenvalue"
	v.TGChatID = "-1001234567890"
	return v
}

// saveBody is the form the Settings page posts, as a map so a test can change
// one field.
func saveBody(v store.Settings) map[string]any {
	return map[string]any{
		"panelUrl": v.PanelURL, "realHost": v.RealHost, "tgChatId": v.TGChatID,
		"downAfter": v.DownAfter, "upAfter": v.UpAfter, "flapN": v.FlapN,
		"flapMin": v.FlapMin, "flapHoldMin": v.FlapHoldMin,
		"clientOfflineAfter": v.ClientOfflineAfter, "panelDownAfter": v.PanelDownAfter,
		"intervalMs": v.IntervalMs, "budgetMs": v.BudgetMs, "connectMs": v.ConnectMs,
		"tlsMs": v.TLSMs, "headersMs": v.HeadersMs, "startJitterMs": v.StartJitterMs,
		"heartbeatTimeoutMs": v.HeartbeatTimeoutMs,
	}
}

// TestSettingsReadMasksTheSecrets: neither token is ever sent to the browser.
func TestSettingsReadMasksTheSecrets(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	rec := h.get("/admin/api/settings", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"mon-token-0123456789abcdef", "1234567890:AAstoredtelegramtokenvalue"} {
		if strings.Contains(body, secret) {
			t.Errorf("the response carries the secret %q", secret)
		}
	}

	var payload settingsPayload
	decodeObj(t, rec, &payload)
	if !payload.RealServer.MonToken.Set || payload.RealServer.MonToken.Hint != "••••cdef" {
		t.Errorf("monToken = %+v, want set with the last four characters", payload.RealServer.MonToken)
	}
	if !payload.Telegram.TGToken.Set || !strings.HasPrefix(payload.Telegram.TGToken.Hint, "••••") {
		t.Errorf("tgToken = %+v, want a masked hint", payload.Telegram.TGToken)
	}
	if payload.RealServer.PanelURL != "https://panel.example.net/secretpath" {
		t.Errorf("panelUrl = %q, want the stored one", payload.RealServer.PanelURL)
	}
	if payload.Telegram.TGChatID != "-1001234567890" {
		t.Errorf("tgChatId = %q, want the stored one", payload.Telegram.TGChatID)
	}
}

// TestMask covers the masking rule itself.
func TestMask(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want maskedSecret
	}{
		{"", maskedSecret{}},
		{"   ", maskedSecret{}},
		{"short", maskedSecret{Set: true, Hint: "••••"}},
		{"0123456789ab", maskedSecret{Set: true, Hint: "••••89ab"}},
	}
	for _, c := range cases {
		if got := mask(c.in); got != c.want {
			t.Errorf("mask(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

// TestSettingsReadCarriesTheStatusLineAndReadOnlyBlocks covers the panel
// status line, the proxy front block and the TLS & admin block of §9.4.
func TestSettingsReadCarriesTheStatusLineAndReadOnlyBlocks(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	state := store.PanelState{
		LastRevision: "rev-7", OverrideEnabled: true, OverrideHost: "front.example.net",
		LastCheckedAt: 1_700_000_000_000, Status: store.PanelStatusUp,
	}
	if err := h.store.SavePanelState(state); err != nil {
		t.Fatalf("save panel state: %v", err)
	}
	inbounds := []store.PanelInbound{
		{InboundKind: "xray", InboundID: 1, SeenRevision: "rev-7"},
		{InboundKind: "xray", InboundID: 2, SeenRevision: "rev-7"},
		{InboundKind: "awg", InboundID: 0, SeenRevision: "rev-6"},
	}
	if err := h.store.DB().Create(&inbounds).Error; err != nil {
		t.Fatalf("seed inbounds: %v", err)
	}
	cookie := h.signIn()

	var payload settingsPayload
	decodeObj(t, h.get("/admin/api/settings", cookie), &payload)

	if !payload.Panel.Reachable || payload.Panel.Revision != "rev-7" {
		t.Errorf("panel = %+v, want a reachable panel at rev-7", payload.Panel)
	}
	if payload.Panel.Inbounds != 2 {
		t.Errorf("inbounds = %d, want 2 (the ones of the last revision)", payload.Panel.Inbounds)
	}
	if !payload.ProxyFront.Enabled || payload.ProxyFront.Host != "front.example.net" {
		t.Errorf("proxyFront = %+v, want the override from the last GET /state", payload.ProxyFront)
	}
	if payload.TLSAdmin.TLSMode != "acme-ip" || payload.TLSAdmin.Listen != ":443" ||
		payload.TLSAdmin.DataDir != "/var/lib/mon-server" || payload.TLSAdmin.AdminHint != DefaultAdminHint {
		t.Errorf("tlsAdmin = %+v, want the bootstrap values and the admin hint", payload.TLSAdmin)
	}
}

// TestSaveAppliesEverythingAtOnce.
func TestSaveAppliesEverythingAtOnce(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	next := storedSettings()
	next.PanelURL = "https://panel2.example.net/other"
	next.DownAfter = 5
	next.FlapMin = 45
	body := saveBody(next)

	rec := h.post("/admin/api/settings", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	stored, err := h.store.Settings()
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if stored.PanelURL != next.PanelURL || stored.DownAfter != 5 || stored.FlapMin != 45 {
		t.Errorf("stored = %+v, want the submitted values", stored)
	}
	// An absent secret keeps the stored one.
	if stored.MonToken != "mon-token-0123456789abcdef" {
		t.Errorf("monToken = %q, want the stored token to survive a Save that did not retype it", stored.MonToken)
	}
	if stored.TGToken != "1234567890:AAstoredtelegramtokenvalue" {
		t.Errorf("tgToken = %q, want the stored token to survive", stored.TGToken)
	}
}

// TestSaveReplacesARetypedSecret.
func TestSaveReplacesARetypedSecret(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	body := saveBody(storedSettings())
	body["monToken"] = "a-brand-new-monitoring-token"
	if rec := h.post("/admin/api/settings", body, cookie); rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	stored, _ := h.store.Settings()
	if stored.MonToken != "a-brand-new-monitoring-token" {
		t.Errorf("monToken = %q, want the retyped one", stored.MonToken)
	}
}

// TestSaveRebuildsConfigsOnProbeChange is the rule of §9.4: a probe parameter
// or realHost changing gives every mon-client a new config revision.
func TestSaveRebuildsConfigsOnProbeChange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		change      func(*store.Settings)
		wantRebuild bool
	}{
		{
			name:        "a probe parameter",
			change:      func(v *store.Settings) { v.IntervalMs = 90_000 },
			wantRebuild: true,
		},
		{
			name:        "the address for path direct",
			change:      func(v *store.Settings) { v.RealHost = "other.example.net" },
			wantRebuild: true,
		},
		{
			name:        "only Telegram",
			change:      func(v *store.Settings) { v.TGChatID = "-1009999999999" },
			wantRebuild: false,
		},
		{
			name:        "only a threshold",
			change:      func(v *store.Settings) { v.DownAfter = 7 },
			wantRebuild: false,
		},
		{
			name:        "nothing at all",
			change:      func(*store.Settings) {},
			wantRebuild: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if err := h.store.SaveSettings(storedSettings()); err != nil {
				t.Fatalf("save settings: %v", err)
			}
			cookie := h.signIn()

			next := storedSettings()
			c.change(&next)
			rec := h.post("/admin/api/settings", saveBody(next), cookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
			}
			var result saveResult
			decodeObj(t, rec, &result)

			wantCalls := 0
			if c.wantRebuild {
				wantCalls = 1
			}
			if got := h.configs.count(); got != wantCalls {
				t.Errorf("rebuilds = %d, want %d", got, wantCalls)
			}
			if result.Rebuilt != c.wantRebuild {
				t.Errorf("rebuilt = %v, want %v", result.Rebuilt, c.wantRebuild)
			}
		})
	}
}

// TestSaveReportsAFailedRebuild: the settings are stored, the failure is told.
func TestSaveReportsAFailedRebuild(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	h.configs.err = errFake
	cookie := h.signIn()

	next := storedSettings()
	next.IntervalMs = 120_000
	rec := h.post("/admin/api/settings", saveBody(next), cookie)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
	stored, _ := h.store.Settings()
	if stored.IntervalMs != 120_000 {
		t.Errorf("intervalMs = %d, want the saved value: the settings are the source of truth", stored.IntervalMs)
	}
}

// TestSaveRefusesUnusableSettings.
func TestSaveRefusesUnusableSettings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		patch map[string]any
		want  string
	}{
		{name: "a panel URL without a scheme", patch: map[string]any{"panelUrl": "panel.example.net"}, want: "http://"},
		{name: "a panel URL without a host", patch: map[string]any{"panelUrl": "https:///path"}, want: "no host"},
		{name: "a whole URL as the direct address", patch: map[string]any{"realHost": "https://real.example.net/"}, want: "not a URL"},
		{name: "downAfter of zero", patch: map[string]any{"downAfter": 0}, want: "Down after"},
		{name: "an absurd probe interval", patch: map[string]any{"intervalMs": 10}, want: "Probe interval"},
		{name: "a budget longer than the interval", patch: map[string]any{"budgetMs": 60000, "intervalMs": 60000}, want: "shorter than the probe interval"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if err := h.store.SaveSettings(storedSettings()); err != nil {
				t.Fatalf("save settings: %v", err)
			}
			cookie := h.signIn()

			body := saveBody(storedSettings())
			for k, v := range c.patch {
				body[k] = v
			}
			rec := h.post("/admin/api/settings", body, cookie)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if env := decode(t, rec); !strings.Contains(env.Msg, c.want) {
				t.Errorf("msg = %q, want it to mention %q", env.Msg, c.want)
			}
			stored, _ := h.store.Settings()
			if !reflect.DeepEqual(stored, storedSettings()) {
				t.Errorf("the settings changed although the Save was refused: %+v", stored)
			}
			if h.configs.count() != 0 {
				t.Error("a refused Save rebuilt the configurations")
			}
		})
	}
}

// TestCheckUsesTypedValuesAndSavesNothing is the Check button of §9.4.
func TestCheckUsesTypedValuesAndSavesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	h.panel.result = PanelCheck{Revision: "rev-9", Inbounds: 4, OverrideEnabled: true, OverrideHost: "front.example.net"}
	cookie := h.signIn()

	body := map[string]any{"panelUrl": "https://typed.example.net/path", "monToken": "typed-token-value"}
	rec := h.post("/admin/api/settings/check", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	want := []panelCall{{URL: "https://typed.example.net/path", Token: "typed-token-value"}}
	if !reflect.DeepEqual(h.panel.calls, want) {
		t.Errorf("panel calls = %+v, want %+v", h.panel.calls, want)
	}
	var result PanelCheck
	decodeObj(t, rec, &result)
	if result.Revision != "rev-9" || result.Inbounds != 4 {
		t.Errorf("result = %+v, want what the panel answered", result)
	}

	stored, _ := h.store.Settings()
	if !reflect.DeepEqual(stored, storedSettings()) {
		t.Errorf("Check changed the stored settings: %+v", stored)
	}
}

// TestCheckFallsBackToTheStoredToken: the token field is empty unless retyped.
func TestCheckFallsBackToTheStoredToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	body := map[string]any{"panelUrl": "https://typed.example.net/path"}
	if rec := h.post("/admin/api/settings/check", body, cookie); rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if len(h.panel.calls) != 1 || h.panel.calls[0].Token != "mon-token-0123456789abcdef" {
		t.Errorf("panel calls = %+v, want the stored token", h.panel.calls)
	}
}

// TestCheckReportsAnUnreachablePanel: a refusal is an answer, not an error.
func TestCheckReportsAnUnreachablePanel(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.panel.err = errFake
	cookie := h.signIn()

	body := map[string]any{"panelUrl": "https://typed.example.net/path", "monToken": "typed"}
	rec := h.post("/admin/api/settings/check", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with success:false", rec.Code)
	}
	env := decode(t, rec)
	if env.Success || !strings.Contains(env.Msg, "unreachable") {
		t.Errorf("envelope = %+v, want an unreachable panel", env)
	}
}

// TestCheckRefusesAnEmptyOrBrokenURL.
func TestCheckRefusesAnEmptyOrBrokenURL(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	for _, body := range []map[string]any{
		{"panelUrl": "", "monToken": "x"},
		{"panelUrl": "not a url", "monToken": "x"},
		{"panelUrl": "https://panel.example.net", "monToken": ""},
	} {
		rec := h.post("/admin/api/settings/check", body, cookie)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %v: status = %d, want 400", body, rec.Code)
		}
	}
	if len(h.panel.calls) != 0 {
		t.Errorf("the panel was called with %+v", h.panel.calls)
	}
}

// TestSendTestUsesTypedValuesAndSavesNothing is the Send test button of §9.4.
func TestSendTestUsesTypedValuesAndSavesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	body := map[string]any{"tgToken": "typed:telegram-token", "tgChatId": "-100777"}
	rec := h.post("/admin/api/settings/test-telegram", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	want := []telegramCall{{Token: "typed:telegram-token", ChatID: "-100777"}}
	if !reflect.DeepEqual(h.telegram.calls, want) {
		t.Errorf("telegram calls = %+v, want %+v", h.telegram.calls, want)
	}
	stored, _ := h.store.Settings()
	if !reflect.DeepEqual(stored, storedSettings()) {
		t.Errorf("Send test changed the stored settings: %+v", stored)
	}
}

// TestSendTestFallsBackToTheStoredToken.
func TestSendTestFallsBackToTheStoredToken(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	body := map[string]any{"tgChatId": "-1001234567890"}
	if rec := h.post("/admin/api/settings/test-telegram", body, cookie); rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if len(h.telegram.calls) != 1 || h.telegram.calls[0].Token != "1234567890:AAstoredtelegramtokenvalue" {
		t.Errorf("telegram calls = %+v, want the stored token", h.telegram.calls)
	}
}

// TestSendTestReportsARefusal.
func TestSendTestReportsARefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.telegram.err = errFake
	cookie := h.signIn()

	body := map[string]any{"tgToken": "typed", "tgChatId": "-100777"}
	rec := h.post("/admin/api/settings/test-telegram", body, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with success:false", rec.Code)
	}
	if env := decode(t, rec); env.Success {
		t.Error("a refused Telegram message reported success")
	}
}

// TestSendTestNeedsBothValues.
func TestSendTestNeedsBothValues(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	rec := h.post("/admin/api/settings/test-telegram", map[string]any{"tgToken": "", "tgChatId": ""}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(h.telegram.calls) != 0 {
		t.Errorf("Telegram was called with %+v", h.telegram.calls)
	}
}

// TestUnwiredServicesAnswerInstead: a Server built without the optional
// services says so rather than panicking.
func TestUnwiredServicesAnswerInstead(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(o *Options) {
		o.Panel = nil
		o.Telegram = nil
		o.Configs = nil
	})
	if err := h.store.SaveSettings(storedSettings()); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	cookie := h.signIn()

	if rec := h.post("/admin/api/settings/check", map[string]any{"panelUrl": "https://p.example/x", "monToken": "t"}, cookie); rec.Code != http.StatusInternalServerError {
		t.Errorf("check: status = %d, want 500", rec.Code)
	}
	if rec := h.post("/admin/api/settings/test-telegram", map[string]any{"tgToken": "t", "tgChatId": "c"}, cookie); rec.Code != http.StatusInternalServerError {
		t.Errorf("test-telegram: status = %d, want 500", rec.Code)
	}
	next := storedSettings()
	next.IntervalMs = 90_000
	if rec := h.post("/admin/api/settings", saveBody(next), cookie); rec.Code != http.StatusInternalServerError {
		t.Errorf("save with a rebuild: status = %d, want 500", rec.Code)
	}
}
