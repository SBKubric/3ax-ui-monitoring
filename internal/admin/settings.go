package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
)

// telegramTestText is what "Send test" sends (spec §9.4). It names
// mon-server so that an administrator who wired the wrong chat can tell at a
// glance which service the stray message came from.
const telegramTestText = "mon-server: Telegram test message. If you can read this, alerts will reach this chat."

// adminCommandHint is the reminder spec §9.4 puts on the "TLS & admin" tab:
// the password is changed on the box, not in this UI.
const adminCommandHint = "mon-server admin set <user>"

// settingsPayload is the Settings page's whole form (spec §9.4), with the
// exact key names the settings table stores. It is one flat object because
// the page has one Save button that "применяет всё разом" — there is no
// per-tab save to make a nested shape worth it.
type settingsPayload struct {
	PanelUrl string `json:"panelUrl"`
	MonToken string `json:"monToken"`
	RealHost string `json:"realHost"`
	PanelCa  string `json:"panelCa"`

	TgToken  string `json:"tgToken"`
	TgChatId string `json:"tgChatId"`

	DownAfter          int `json:"downAfter"`
	UpAfter            int `json:"upAfter"`
	FlapN              int `json:"flapN"`
	FlapMin            int `json:"flapMin"`
	FlapHoldMin        int `json:"flapHoldMin"`
	ClientOfflineAfter int `json:"clientOfflineAfter"`
	PanelDownAfter     int `json:"panelDownAfter"`

	IntervalMs         int64 `json:"intervalMs"`
	BudgetMs           int64 `json:"budgetMs"`
	ConnectMs          int64 `json:"connectMs"`
	TlsMs              int64 `json:"tlsMs"`
	HeadersMs          int64 `json:"headersMs"`
	StartJitterMs      int64 `json:"startJitterMs"`
	HeartbeatTimeoutMs int64 `json:"heartbeatTimeoutMs"`
}

// toPayload / toSettings convert between the wire shape and store.Settings.
// They are written out field by field on purpose: a field added to
// store.Settings without a line here is a field the admin UI silently could
// not edit, and an explicit list makes that omission visible in review.
func toPayload(s *store.Settings) settingsPayload {
	return settingsPayload{
		PanelUrl: s.PanelURL, MonToken: s.MonToken, RealHost: s.RealHost, PanelCa: s.PanelCA,
		TgToken: s.TgToken, TgChatId: s.TgChatID,
		DownAfter: s.DownAfter, UpAfter: s.UpAfter, FlapN: s.FlapN, FlapMin: s.FlapMin,
		FlapHoldMin: s.FlapHoldMin, ClientOfflineAfter: s.ClientOfflineAfter, PanelDownAfter: s.PanelDownAfter,
		IntervalMs: s.IntervalMs, BudgetMs: s.BudgetMs, ConnectMs: s.ConnectMs, TlsMs: s.TlsMs,
		HeadersMs: s.HeadersMs, StartJitterMs: s.StartJitterMs, HeartbeatTimeoutMs: s.HeartbeatTimeoutMs,
	}
}

func (p settingsPayload) toSettings() *store.Settings {
	return &store.Settings{
		PanelURL: strings.TrimSpace(p.PanelUrl), MonToken: strings.TrimSpace(p.MonToken), RealHost: strings.TrimSpace(p.RealHost),
		PanelCA: strings.TrimSpace(p.PanelCa),
		TgToken: strings.TrimSpace(p.TgToken), TgChatID: strings.TrimSpace(p.TgChatId),
		DownAfter: p.DownAfter, UpAfter: p.UpAfter, FlapN: p.FlapN, FlapMin: p.FlapMin,
		FlapHoldMin: p.FlapHoldMin, ClientOfflineAfter: p.ClientOfflineAfter, PanelDownAfter: p.PanelDownAfter,
		IntervalMs: p.IntervalMs, BudgetMs: p.BudgetMs, ConnectMs: p.ConnectMs, TlsMs: p.TlsMs,
		HeadersMs: p.HeadersMs, StartJitterMs: p.StartJitterMs, HeartbeatTimeoutMs: p.HeartbeatTimeoutMs,
	}
}

// validate rejects a negative number in any field (spec §9.4's thresholds
// and probe parameters are all counts or milliseconds; none of them has a
// meaning below zero, and a negative probe timeout would be handed to every
// mon-client in its config) and a panelCa that is not a PEM certificate
// chain (decision #52 §1). The message names the field so the page can
// point at it.
func (p settingsPayload) validate() error {
	if _, err := panel.ParseCA(p.PanelCa); err != nil {
		return err
	}
	ints := []struct {
		name string
		v    int
	}{
		{"downAfter", p.DownAfter}, {"upAfter", p.UpAfter}, {"flapN", p.FlapN}, {"flapMin", p.FlapMin},
		{"flapHoldMin", p.FlapHoldMin}, {"clientOfflineAfter", p.ClientOfflineAfter}, {"panelDownAfter", p.PanelDownAfter},
	}
	for _, f := range ints {
		if f.v < 0 {
			return errors.New(f.name + " must be zero or more")
		}
	}
	int64s := []struct {
		name string
		v    int64
	}{
		{"intervalMs", p.IntervalMs}, {"budgetMs", p.BudgetMs}, {"connectMs", p.ConnectMs}, {"tlsMs", p.TlsMs},
		{"headersMs", p.HeadersMs}, {"startJitterMs", p.StartJitterMs}, {"heartbeatTimeoutMs", p.HeartbeatTimeoutMs},
	}
	for _, f := range int64s {
		if f.v < 0 {
			return errors.New(f.name + " must be zero or more")
		}
	}
	return nil
}

// rebuildTriggered reports whether the saved settings change anything that
// appears in a mon-client's config document (spec §9.4: "смена probe-
// параметров или realHost пересобирает client_configs всем mon-clients").
// Nothing else in Settings reaches a mon-client, so nothing else may force
// every box to re-fetch its config.
func rebuildTriggered(old, updated *store.Settings) bool {
	return old.RealHost != updated.RealHost ||
		old.IntervalMs != updated.IntervalMs ||
		old.BudgetMs != updated.BudgetMs ||
		old.ConnectMs != updated.ConnectMs ||
		old.TlsMs != updated.TlsMs ||
		old.HeadersMs != updated.HeadersMs ||
		old.StartJitterMs != updated.StartJitterMs ||
		old.HeartbeatTimeoutMs != updated.HeartbeatTimeoutMs
}

// getSettings answers the Settings page: the editable settings, the panel
// status line, the read-only proxy front from the last GET /state, and the
// read-only bootstrap block (spec §9.4).
func (h *Handler) getSettings(c *gin.Context) {
	set, err := h.deps.Store.LoadSettings()
	if err != nil {
		slog.Error("admin: loading settings failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not load settings.")
		return
	}
	ok(c, gin.H{
		"settings":  toPayload(set),
		"panel":     h.panelStatus(c, set),
		"bootstrap": h.bootstrapBlock(),
		"now":       clock.Ms(h.deps.Clock.Now()),
	})
}

// panelStatus is the status line above the tabs (spec §9.4: "Panel
// reachable · revision · N inbounds · override → host"). revision and the
// override come from the poller's last accepted material, the inbound count
// from the panel_inbounds mirror the same poll wrote, and "reachable" from
// the poller's PANEL_DOWN state (spec §4.1) — the admin UI never polls the
// panel itself just to draw this line.
func (h *Handler) panelStatus(c *gin.Context, set *store.Settings) gin.H {
	status := gin.H{
		"configured":       set.PanelURL != "" && set.MonToken != "",
		"reachable":        false,
		"unknownAuthority": false,
		"polled":           false,
		"revision":         "",
		"inbounds":         0,
		"override":         gin.H{"enabled": false, "host": ""},
	}
	if h.deps.Poller == nil {
		return status
	}
	status["reachable"] = !h.deps.Poller.PanelDown()
	// Decision #52 §1: an untrusted panel certificate gets its own text on
	// the status line, pointing at panelCa, rather than a bare
	// "unreachable" (or "not polled yet", which is all a panel that has
	// never passed the handshake would otherwise show).
	status["unknownAuthority"] = h.deps.Poller.UnknownAuthority()

	material, have := h.deps.Poller.Material()
	if !have {
		return status
	}
	status["polled"] = true
	status["revision"] = material.Revision
	status["override"] = gin.H{"enabled": material.Override.Enabled, "host": material.Override.Host}

	var n int64
	if err := h.deps.Store.DB.WithContext(c.Request.Context()).
		Model(&store.PanelInbound{}).Count(&n).Error; err != nil {
		slog.Warn("admin: counting panel inbounds failed", "err", err)
	}
	status["inbounds"] = n
	return status
}

// bootstrapBlock is the read-only "TLS & admin" tab (spec §9.4): what the
// bootstrap config fixed at start-up, the certificate's window, and the
// reminder that the password is changed on the box.
func (h *Handler) bootstrapBlock() gin.H {
	out := gin.H{
		"listen":        h.listen(),
		"publicIp":      h.publicIP(),
		"dataDir":       "",
		"tlsMode":       "",
		"acmeCa":        "",
		"acmeDirectory": "",
		"adminCommand":  adminCommandHint,
		"cert":          nil,
	}
	if h.deps.Cfg == nil {
		return out
	}
	out["dataDir"] = h.deps.Cfg.DataDir
	out["tlsMode"] = h.deps.Cfg.TLS.Mode
	// tls.acmeCa (decision #52 §2): the name as configured and the ACME
	// directory it resolves to, so a stand on staging is visibly so.
	out["acmeCa"] = h.deps.Cfg.TLS.ACMECA
	out["acmeDirectory"] = tlsx.ACMEDirectory(h.deps.Cfg.TLS.ACMECA)

	info, err := tlsx.InspectCert(h.deps.Cfg.TLS, h.deps.Cfg.DataDir)
	if err != nil {
		slog.Warn("admin: reading the TLS certificate failed", "err", err)
		return out
	}
	if info != nil {
		cert := gin.H{
			"subject":   info.Subject,
			"notBefore": clock.Ms(info.NotBefore),
			"notAfter":  clock.Ms(info.NotAfter),
			"renewAt":   nil,
		}
		if !info.RenewAt.IsZero() {
			cert["renewAt"] = clock.Ms(info.RenewAt)
		}
		out["cert"] = cert
	}
	return out
}

// saveSettings applies the whole form at once (spec §9.4: "Save применяет
// всё разом") and rebuilds every mon-client's config document when a probe
// parameter or realHost changed, which gives each of them a new config
// revision to fetch. The rebuild happens after the save, so a mon-client
// that asks for its config mid-rebuild gets either the old document or the
// new one, never a document built from half-saved settings.
func (h *Handler) saveSettings(c *gin.Context) {
	var body settingsPayload
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed settings.")
		return
	}
	if err := body.validate(); err != nil {
		fail(c, http.StatusBadRequest, err.Error()+".")
		return
	}

	old, err := h.deps.Store.LoadSettings()
	if err != nil {
		slog.Error("admin: loading settings before a save failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not load settings.")
		return
	}
	updated := body.toSettings()
	if err := h.deps.Store.SaveSettings(updated); err != nil {
		slog.Error("admin: saving settings failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not save settings.")
		return
	}

	rebuilt := false
	if rebuildTriggered(old, updated) && h.deps.Configs != nil {
		if err := h.deps.Configs.RebuildAll(c.Request.Context()); err != nil {
			// The settings are already saved and correct; a failed rebuild
			// is redone by the next panel revision, so this is a warning to
			// the administrator, not a failed save.
			slog.Error("admin: rebuilding mon-client configs after a settings save failed", "err", err)
			okMsg(c, "Saved, but rebuilding the mon-client configs failed — the next panel poll will retry.", gin.H{"settings": toPayload(updated), "rebuilt": false})
			return
		}
		rebuilt = true
	}

	msg := "Saved."
	if rebuilt {
		msg = "Saved. Every mon-client config was rebuilt with a new revision."
	}
	okMsg(c, msg, gin.H{"settings": toPayload(updated), "rebuilt": rebuilt})
}

// checkBody is the "Check" button's submission: the values currently typed
// into the form, which is the whole point — spec §9.4 checks "по введённым
// значениям, без Save", so an administrator can find out whether a new URL
// or token works *before* committing it.
type checkBody struct {
	PanelUrl string `json:"panelUrl"`
	MonToken string `json:"monToken"`
	PanelCa  string `json:"panelCa"`
}

// msgUnknownAuthority is Check's text for a panel certificate that the
// current trust does not cover (decision #52 §1): the cure is specific, so
// the message names it instead of lumping it in with "did not answer".
const msgUnknownAuthority = "The panel's TLS certificate is not trusted (x509: certificate signed by unknown authority). " +
	"If the panel uses a self-signed or private certificate, paste it (PEM) into Panel CA — " +
	"mon-server then trusts exactly that chain for the panel instead of the system CAs."

// checkPanel calls GET /state with the submitted credentials — panelCa
// included — and reports what came back. It saves nothing, touches no settings row, and never
// disturbs the poll loop's own client.
func (h *Handler) checkPanel(c *gin.Context) {
	var body checkBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed check.")
		return
	}
	url := strings.TrimSpace(body.PanelUrl)
	token := strings.TrimSpace(body.MonToken)
	if url == "" || token == "" {
		fail(c, http.StatusBadRequest, "Panel URL and monitoring token are both required.")
		return
	}
	roots, err := panel.ParseCA(body.PanelCa)
	if err != nil {
		fail(c, http.StatusBadRequest, err.Error()+".")
		return
	}

	st, err := h.deps.NewPanelClient(url, token, roots).State(c.Request.Context())
	if err != nil {
		if panel.IsUnknownAuthority(err) {
			fail(c, http.StatusBadGateway, msgUnknownAuthority)
			return
		}
		// A bare 404 is the panel's deliberate answer to anyone without a
		// valid monToken, and to everyone when monitoring is switched off
		// (contract §2) — it is never "no such route", so the message has
		// to spell out all three possibilities rather than echo a 404.
		if errors.Is(err, panel.ErrNotFound) {
			fail(c, http.StatusBadGateway, "The panel answered 404: wrong monitoring token, wrong panel URL (check the webBasePath), or monitoring is switched off in the panel.")
			return
		}
		fail(c, http.StatusBadGateway, "The panel did not answer: "+err.Error())
		return
	}

	subID := ""
	if st.Probe.SubId != nil {
		subID = *st.Probe.SubId
	}
	okMsg(c, "Panel reachable.", gin.H{
		"revision":     st.Revision,
		"inbounds":     len(st.Inbounds),
		"override":     gin.H{"enabled": st.Override.Enabled, "host": st.Override.Host},
		"panelVersion": st.PanelVersion,
		"serverTime":   st.ServerTime,
		"probeSubId":   subID,
	})
}

// telegramBody is the "Send test" button's submission — again the values
// typed into the form, not the saved ones (spec §9.4: "без Save").
type telegramBody struct {
	TgToken  string `json:"tgToken"`
	TgChatId string `json:"tgChatId"`
}

// telegramTest sends one message with the submitted bot token and chat id.
// Nothing is saved: the administrator is checking credentials, and a token
// that turns out to be wrong should never end up in the settings table
// because they pressed the test button.
func (h *Handler) telegramTest(c *gin.Context) {
	var body telegramBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed request.")
		return
	}
	token := strings.TrimSpace(body.TgToken)
	chat := strings.TrimSpace(body.TgChatId)
	if token == "" || chat == "" {
		fail(c, http.StatusBadRequest, "Bot token and chat id are both required.")
		return
	}
	if h.deps.Telegram == nil {
		fail(c, http.StatusInternalServerError, "Telegram is not wired in this process.")
		return
	}

	if err := h.deps.Telegram.SendTo(c.Request.Context(), token, chat, telegramTestText); err != nil {
		fail(c, http.StatusBadGateway, "Telegram refused the message: "+err.Error())
		return
	}
	okMsg(c, "Test message sent.", nil)
}
