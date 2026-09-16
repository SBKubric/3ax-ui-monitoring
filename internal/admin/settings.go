package admin

import (
	"net/http"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// settingsPayload is the obj of GET /admin/api/settings: the five tabs of
// §9.4 and the status line above them.
type settingsPayload struct {
	ServerTime int64            `json:"serverTime"`
	Pending    int              `json:"pending"`
	RealServer realServerTab    `json:"realServer"`
	ProxyFront proxyFrontBlock  `json:"proxyFront"`
	Telegram   telegramTab      `json:"telegram"`
	Thresholds thresholdsTab    `json:"thresholds"`
	Probe      probeTab         `json:"probe"`
	TLSAdmin   ServerInfo       `json:"tlsAdmin"`
	Panel      panelStatusBlock `json:"panel"`
}

// realServerTab is the Real server tab. The monitoring token is never sent
// back to the browser: only whether one is stored and its last characters.
type realServerTab struct {
	PanelURL string       `json:"panelUrl"`
	MonToken maskedSecret `json:"monToken"`
	RealHost string       `json:"realHost"`
}

// proxyFrontBlock is the read-only proxy front of §9.4: mon-server has no
// setting of its own for it, the values come from the last GET /state.
type proxyFrontBlock struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	SeenAt  int64  `json:"seenAt"`
}

// telegramTab is the Telegram tab; the bot token is masked like monToken.
type telegramTab struct {
	TGToken  maskedSecret `json:"tgToken"`
	TGChatID string       `json:"tgChatId"`
}

// thresholdsTab is the Thresholds tab (§7.2, §7.3, §4.1).
type thresholdsTab struct {
	DownAfter          int `json:"downAfter"`
	UpAfter            int `json:"upAfter"`
	FlapN              int `json:"flapN"`
	FlapMin            int `json:"flapMin"`
	FlapHoldMin        int `json:"flapHoldMin"`
	ClientOfflineAfter int `json:"clientOfflineAfter"`
	PanelDownAfter     int `json:"panelDownAfter"`
}

// probeTab is the Probe tab: the parameters every mon-client gets in its
// configuration document (§5). Changing any of them rebuilds every config.
type probeTab struct {
	IntervalMs         int `json:"intervalMs"`
	BudgetMs           int `json:"budgetMs"`
	ConnectMs          int `json:"connectMs"`
	TLSMs              int `json:"tlsMs"`
	HeadersMs          int `json:"headersMs"`
	StartJitterMs      int `json:"startJitterMs"`
	HeartbeatTimeoutMs int `json:"heartbeatTimeoutMs"`
}

// panelStatusBlock is the status line of §9.4: "Panel reachable · revision ·
// N inbounds · override → host · checked N ago", or the last error.
type panelStatusBlock struct {
	// Status is PANEL_UP, PANEL_DOWN or UNKNOWN before the first poll.
	Status          string `json:"status"`
	Reachable       bool   `json:"reachable"`
	Revision        string `json:"revision"`
	Inbounds        int    `json:"inbounds"`
	OverrideEnabled bool   `json:"overrideEnabled"`
	OverrideHost    string `json:"overrideHost"`
	CheckedAt       int64  `json:"checkedAt"`
	Error           string `json:"error"`
}

// maskedSecret is how a stored secret reaches the browser (§9.4): never the
// value, only that one is stored and enough of its tail to tell two apart.
type maskedSecret struct {
	Set bool `json:"set"`
	// Hint is the masked form, for example "••••9f2a". It is empty when
	// nothing is stored.
	Hint string `json:"hint"`
}

// maskLength is the shortest secret whose last characters are shown. Below it
// four characters would be a large part of the value, so nothing is revealed.
const maskLength = 12

// mask renders a stored secret for the browser.
func mask(value string) maskedSecret {
	value = strings.TrimSpace(value)
	if value == "" {
		return maskedSecret{}
	}
	const dots = "••••"
	runes := []rune(value)
	if len(runes) < maskLength {
		return maskedSecret{Set: true, Hint: dots}
	}
	return maskedSecret{Set: true, Hint: dots + string(runes[len(runes)-4:])}
}

// apiSettings returns the settings, the panel status line and the read-only
// blocks of §9.4.
func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	values, err := s.store.Settings()
	if err != nil {
		s.writeServiceError(w, r, "reading the settings", err)
		return
	}
	panelState, err := s.store.PanelState()
	if err != nil {
		s.writeServiceError(w, r, "reading the panel state", err)
		return
	}
	inbounds, err := s.inboundCount(panelState.LastRevision)
	if err != nil {
		s.writeServiceError(w, r, "counting the panel's inbounds", err)
		return
	}
	pending, err := s.registry.PendingCount(r.Context())
	if err != nil {
		s.writeServiceError(w, r, "counting registration requests", err)
		return
	}

	writeOK(w, "", settingsPayload{
		ServerTime: s.nowMS(),
		Pending:    pending,
		RealServer: realServerTab{
			PanelURL: values.PanelURL,
			MonToken: mask(values.MonToken),
			RealHost: values.RealHost,
		},
		ProxyFront: proxyFrontBlock{
			Enabled: panelState.OverrideEnabled,
			Host:    panelState.OverrideHost,
			SeenAt:  panelState.LastCheckedAt,
		},
		Telegram: telegramTab{
			TGToken:  mask(values.TGToken),
			TGChatID: values.TGChatID,
		},
		Thresholds: thresholdsTab{
			DownAfter:          values.DownAfter,
			UpAfter:            values.UpAfter,
			FlapN:              values.FlapN,
			FlapMin:            values.FlapMin,
			FlapHoldMin:        values.FlapHoldMin,
			ClientOfflineAfter: values.ClientOfflineAfter,
			PanelDownAfter:     values.PanelDownAfter,
		},
		Probe: probeTab{
			IntervalMs:         values.IntervalMs,
			BudgetMs:           values.BudgetMs,
			ConnectMs:          values.ConnectMs,
			TLSMs:              values.TLSMs,
			HeadersMs:          values.HeadersMs,
			StartJitterMs:      values.StartJitterMs,
			HeartbeatTimeoutMs: values.HeartbeatTimeoutMs,
		},
		TLSAdmin: s.info,
		Panel: panelStatusBlock{
			Status:          panelState.Status,
			Reachable:       panelState.Status == store.PanelStatusUp,
			Revision:        panelState.LastRevision,
			Inbounds:        inbounds,
			OverrideEnabled: panelState.OverrideEnabled,
			OverrideHost:    panelState.OverrideHost,
			CheckedAt:       panelState.LastCheckedAt,
			Error:           panelState.LastError,
		},
	})
}

// inboundCount is how many inbounds the last GET /state carried. Rows from an
// older revision are inbounds that have since disappeared from the panel.
func (s *Server) inboundCount(revision string) (int, error) {
	q := s.store.DB().Model(&store.PanelInbound{})
	if revision != "" {
		q = q.Where("seen_revision = ?", revision)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return 0, err
	}
	return int(n), nil
}

// saveSettingsRequest is the body of POST /admin/api/settings. Every field is
// a pointer: an absent field keeps what is stored, which is how the two secret
// fields stay empty in the form without being erased on every Save.
type saveSettingsRequest struct {
	PanelURL *string `json:"panelUrl"`
	MonToken *string `json:"monToken"`
	RealHost *string `json:"realHost"`

	TGToken  *string `json:"tgToken"`
	TGChatID *string `json:"tgChatId"`

	DownAfter          *int `json:"downAfter"`
	UpAfter            *int `json:"upAfter"`
	FlapN              *int `json:"flapN"`
	FlapMin            *int `json:"flapMin"`
	FlapHoldMin        *int `json:"flapHoldMin"`
	ClientOfflineAfter *int `json:"clientOfflineAfter"`
	PanelDownAfter     *int `json:"panelDownAfter"`

	IntervalMs         *int `json:"intervalMs"`
	BudgetMs           *int `json:"budgetMs"`
	ConnectMs          *int `json:"connectMs"`
	TLSMs              *int `json:"tlsMs"`
	HeadersMs          *int `json:"headersMs"`
	StartJitterMs      *int `json:"startJitterMs"`
	HeartbeatTimeoutMs *int `json:"heartbeatTimeoutMs"`
}

// saveResult is the obj of a successful Save: what changed and whether the
// configurations had to be rebuilt.
type saveResult struct {
	// Rebuilt is true when a probe parameter or realHost changed and every
	// mon-client got a new configuration document (§5, §9.4).
	Rebuilt bool `json:"rebuilt"`
}

// apiSaveSettings applies the whole form at once and rebuilds every
// mon-client's configuration when a probe parameter or realHost changed (§9.4).
func (s *Server) apiSaveSettings(w http.ResponseWriter, r *http.Request) {
	var body saveSettingsRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	current, err := s.store.Settings()
	if err != nil {
		s.writeServiceError(w, r, "reading the settings", err)
		return
	}

	next := current
	applyString(&next.PanelURL, body.PanelURL)
	applyString(&next.MonToken, body.MonToken)
	applyString(&next.RealHost, body.RealHost)
	applyString(&next.TGToken, body.TGToken)
	applyString(&next.TGChatID, body.TGChatID)
	applyInt(&next.DownAfter, body.DownAfter)
	applyInt(&next.UpAfter, body.UpAfter)
	applyInt(&next.FlapN, body.FlapN)
	applyInt(&next.FlapMin, body.FlapMin)
	applyInt(&next.FlapHoldMin, body.FlapHoldMin)
	applyInt(&next.ClientOfflineAfter, body.ClientOfflineAfter)
	applyInt(&next.PanelDownAfter, body.PanelDownAfter)
	applyInt(&next.IntervalMs, body.IntervalMs)
	applyInt(&next.BudgetMs, body.BudgetMs)
	applyInt(&next.ConnectMs, body.ConnectMs)
	applyInt(&next.TLSMs, body.TLSMs)
	applyInt(&next.HeadersMs, body.HeadersMs)
	applyInt(&next.StartJitterMs, body.StartJitterMs)
	applyInt(&next.HeartbeatTimeoutMs, body.HeartbeatTimeoutMs)

	if err := validateSettings(next); err != nil {
		writeFail(w, http.StatusBadRequest, "%s", err.Error())
		return
	}

	rebuild := configAffecting(current) != configAffecting(next)
	if err := s.store.SaveSettings(next); err != nil {
		s.writeServiceError(w, r, "saving the settings", err)
		return
	}
	s.log.Info("settings saved", "rebuildConfigs", rebuild)

	if !rebuild {
		writeOK(w, "Settings saved.", saveResult{})
		return
	}
	if s.configs == nil {
		s.log.Error("no configuration rebuilder is wired")
		writeFail(w, http.StatusInternalServerError, "Settings saved, but the configuration rebuild is not wired.")
		return
	}
	if err := s.configs.RebuildAll(r.Context()); err != nil {
		s.log.Error("configuration rebuild failed", "error", err)
		writeFail(w, http.StatusInternalServerError, "Settings saved, but rebuilding the mon-client configurations failed: %s", err.Error())
		return
	}
	writeOK(w, "Settings saved. Every mon-client configuration was rebuilt, so they all have a new config revision.", saveResult{Rebuilt: true})
}

// configInputs is the part of the settings a mon-client's configuration
// document is built from (§5): the probe parameters and the address used for
// path "direct". It is comparable on purpose — Save rebuilds every
// configuration exactly when this changes.
type configInputs struct {
	probeTab
	RealHost string
}

// configAffecting extracts those inputs.
func configAffecting(v store.Settings) configInputs {
	return configInputs{
		probeTab: probeTab{
			IntervalMs:         v.IntervalMs,
			BudgetMs:           v.BudgetMs,
			ConnectMs:          v.ConnectMs,
			TLSMs:              v.TLSMs,
			HeadersMs:          v.HeadersMs,
			StartJitterMs:      v.StartJitterMs,
			HeartbeatTimeoutMs: v.HeartbeatTimeoutMs,
		},
		RealHost: v.RealHost,
	}
}

// checkPanelRequest is the body of POST /admin/api/settings/check: the two
// values as typed. A field left out falls back to what is stored, which is how
// Check works without retyping the token.
type checkPanelRequest struct {
	PanelURL *string `json:"panelUrl"`
	MonToken *string `json:"monToken"`
}

// apiCheckPanel runs one GET /state with the typed values and saves nothing
// (§9.4).
func (s *Server) apiCheckPanel(w http.ResponseWriter, r *http.Request) {
	var body checkPanelRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	stored, err := s.store.Settings()
	if err != nil {
		s.writeServiceError(w, r, "reading the settings", err)
		return
	}
	panelURL := strings.TrimSpace(valueOr(body.PanelURL, stored.PanelURL))
	monToken := valueOr(body.MonToken, stored.MonToken)
	if panelURL == "" {
		writeFail(w, http.StatusBadRequest, "the panel URL is required")
		return
	}
	if err := validPanelURL(panelURL); err != nil {
		writeFail(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	if strings.TrimSpace(monToken) == "" {
		writeFail(w, http.StatusBadRequest, "the monitoring token is required")
		return
	}
	if s.panel == nil {
		writeFail(w, http.StatusInternalServerError, "the panel client is not wired")
		return
	}

	result, err := s.panel.CheckPanel(r.Context(), panelURL, monToken)
	if err != nil {
		// Not an internal failure: an unreachable panel or a rejected token
		// is the answer the administrator asked for.
		s.log.Warn("panel check failed", "panelUrl", panelURL, "error", err)
		writeFail(w, http.StatusOK, "Panel unreachable: %s", err.Error())
		return
	}
	writeOK(w, "Panel reachable.", result)
}

// telegramTestRequest is the body of POST /admin/api/settings/test-telegram.
type telegramTestRequest struct {
	TGToken  *string `json:"tgToken"`
	TGChatID *string `json:"tgChatId"`
}

// apiTestTelegram sends one message with the typed values and saves nothing
// (§9.4).
func (s *Server) apiTestTelegram(w http.ResponseWriter, r *http.Request) {
	var body telegramTestRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	stored, err := s.store.Settings()
	if err != nil {
		s.writeServiceError(w, r, "reading the settings", err)
		return
	}
	token := strings.TrimSpace(valueOr(body.TGToken, stored.TGToken))
	chatID := strings.TrimSpace(valueOr(body.TGChatID, stored.TGChatID))
	if token == "" || chatID == "" {
		writeFail(w, http.StatusBadRequest, "both the bot token and the chat id are required")
		return
	}
	if s.telegram == nil {
		writeFail(w, http.StatusInternalServerError, "the Telegram sender is not wired")
		return
	}
	if err := s.telegram.SendTestMessage(r.Context(), token, chatID); err != nil {
		s.log.Warn("telegram test failed", "chatId", chatID, "error", err)
		writeFail(w, http.StatusOK, "Telegram refused the message: %s", err.Error())
		return
	}
	writeOK(w, "Test message sent.", nil)
}

// applyString writes a submitted value over the stored one, leaving it alone
// when the field was absent.
func applyString(dst *string, value *string) {
	if value != nil {
		*dst = strings.TrimSpace(*value)
	}
}

// applyInt is applyString for a number.
func applyInt(dst *int, value *int) {
	if value != nil {
		*dst = *value
	}
}

// valueOr is the submitted value, or the stored one when the field was absent.
func valueOr(value *string, stored string) string {
	if value == nil {
		return stored
	}
	return *value
}
