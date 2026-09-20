// Package admin is mon-server's admin UI (spec §9): the four surfaces an
// administrator ever sees — login, Requests, mon-clients, Settings — served
// as server-rendered html/template pages with one Vue 3 + Ant Design Vue
// application each, plus the JSON handles under /admin/api/* those
// applications call. Everything it serves (pages and the Vue/antd UMD
// bundles alike) is embedded in the binary by the top-level web package, so
// an install is still one file and the build needs no Node (spec §9.1).
//
// The package owns admin sessions and the per-IP login lockout, and nothing
// else: every decision about the registry, the config documents or the
// settings belongs to internal/registry and internal/store, which this
// package only calls. That is deliberate — the admin UI is a client of
// mon-server's domain, not a second copy of it.
package admin

import (
	"context"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/web"
)

// PanelStatus is the little the admin UI needs to know about the panel poll
// loop for the Settings page's status line (spec §9.4: "Panel reachable ·
// revision · N inbounds · override → host"). *panel.Poller satisfies it; it
// is an interface rather than the concrete poller so a handler test can
// describe a panel state in three lines instead of driving a real poll
// cycle. A nil PanelStatus means "no poll loop wired yet", which the UI
// shows as "never polled" rather than failing.
type PanelStatus interface {
	// Material is the last probe material accepted from the panel, and
	// whether there is any yet (spec §4).
	Material() (panel.Material, bool)
	// PanelDown reports whether mon-server currently considers the panel
	// unreachable (spec §4.1).
	PanelDown() bool
}

// TelegramSender is the Telegram Bot API call behind the Settings page's
// "Send test" button (spec §9.4). *tg.HTTP satisfies it; an interface keeps
// the button testable against an httptest server without this package
// knowing how tg builds its URLs.
type TelegramSender interface {
	SendTo(ctx context.Context, token, chatID, text string) error
}

// Deps are the admin UI's collaborators, injected rather than constructed
// here so tests can pass a temp store, a Fake clock, a paneltest stub and a
// recording Telegram (architecture brief §4).
type Deps struct {
	Store *store.Store
	Clock clock.Clock

	// Registry serves the Requests and mon-clients pages: approve, reject,
	// edit, enable, revoke, delete (spec §9.2, §9.3).
	Registry *registry.Registry
	// Configs is what Settings Save rebuilds when a probe parameter or
	// realHost changes (spec §9.4), and where the mon-clients page reads
	// each client's current server-side config revision.
	Configs *registry.ConfigBuilder
	// Poller supplies the Settings page's panel status line. May be nil.
	Poller PanelStatus
	// Cfg is the bootstrap config shown read-only on the "TLS & admin" tab
	// (spec §9.4): tls.mode, dataDir, listen.
	Cfg *config.Config

	// NewPanelClient builds the client the Settings page's "Check" button
	// uses against the *submitted* panel URL and token, without saving them
	// (spec §9.4). Defaults to panel.NewHTTPClient.
	NewPanelClient func(baseURL, token string) panel.Client
	// Telegram is the "Send test" button's sender. May be nil, in which
	// case the button reports that Telegram is not wired.
	Telegram TelegramSender
}

// Handler is the mounted admin UI. One process has exactly one; it holds no
// mutable state of its own — sessions live in the database, so a restart
// does not log the administrator out and two processes could serve the same
// database if one ever wanted to.
type Handler struct {
	deps  Deps
	pages map[string]*template.Template
}

// New builds the Handler and parses every page template up front, so a
// broken template is a start-up failure rather than a 500 the first time an
// administrator opens that page. It panics on a template that will not
// parse for the same reason: the templates are embedded in the binary, so a
// parse failure can only ever be a build-time mistake, never anything an
// operator could fix at runtime.
func New(d Deps) *Handler {
	if d.NewPanelClient == nil {
		d.NewPanelClient = func(baseURL, token string) panel.Client {
			return panel.NewHTTPClient(baseURL, token, d.Clock)
		}
	}
	return &Handler{deps: d, pages: web.MustParsePages()}
}

// Mount registers every admin route on the group internal/api created for
// it (api.Server.Admin, rooted at /admin). The split is exactly spec §9.1's:
// /admin/login and the embedded assets are reachable without a session
// (nothing else could render the login page), and everything else goes
// through RequireSession — pages redirect to the login form, /admin/api/*
// answers 401 so a Vue application gets a status it can branch on instead of
// a login page parsed as JSON.
func (h *Handler) Mount(admin *gin.RouterGroup) {
	admin.GET("/assets/*filepath", h.asset)

	admin.GET("/login", h.loginPage)
	admin.POST("/login", h.login)
	admin.POST("/logout", h.logout)

	pages := admin.Group("", h.RequireSession(true))
	// Both spellings of the root land on Requests: an administrator who
	// types /admin without the slash should not get a 404 (spec §9.2 makes
	// Requests the first page).
	pages.GET("", h.index)
	pages.GET("/", h.index)
	pages.GET("/requests", h.page("requests"))
	pages.GET("/clients", h.page("clients"))
	pages.GET("/settings", h.page("settings"))

	api := admin.Group("/api", h.RequireSession(false), requireXHR())
	api.GET("/requests", h.listRequests)
	api.POST("/requests/:id/approve", h.approveRequest)
	api.POST("/requests/:id/reject", h.rejectRequest)

	api.GET("/clients", h.listClients)
	api.POST("/clients/:id", h.updateClient)
	api.POST("/clients/:id/enabled", h.setClientEnabled)
	api.POST("/clients/:id/revoke", h.revokeClient)
	api.POST("/clients/:id/delete", h.deleteClient)

	api.GET("/settings", h.getSettings)
	api.POST("/settings", h.saveSettings)
	api.POST("/settings/check", h.checkPanel)
	api.POST("/settings/telegram-test", h.telegramTest)
}

// index sends /admin and /admin/ to the Requests page (spec §9.2: the
// pending-requests page is where an administrator starts).
func (h *Handler) index(c *gin.Context) {
	c.Redirect(http.StatusFound, "/admin/requests")
}

// envelope is the admin UI's answer shape on every /admin/api/* route
// (spec §9.1: "{success, msg, obj} как панель"). It is the panel's own
// envelope on purpose: the administrator's browser talks to two services
// that look and behave alike.
type envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     any    `json:"obj"`
}

// ok answers with a payload and no message — the shape every GET uses.
func ok(c *gin.Context, obj any) {
	c.JSON(http.StatusOK, envelope{Success: true, Obj: obj})
}

// okMsg answers with a message the UI shows as a toast, plus an optional
// payload — the shape every successful mutation uses.
func okMsg(c *gin.Context, msg string, obj any) {
	c.JSON(http.StatusOK, envelope{Success: true, Msg: msg, Obj: obj})
}

// fail answers with success:false and aborts, so a handler can fail and
// return without separately remembering to abort (the same reasoning as
// api.Fail for /v1/*).
func fail(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, envelope{Success: false, Msg: msg})
}

// xhrHeader / xhrValue are the CSRF guard on every mutating /admin/api/*
// request. A cross-site form post or image load cannot set a custom header
// without a successful CORS preflight, which this server never grants, so
// requiring one is enough on top of the session cookie's SameSite=Lax (spec
// §9.1) — and costs nothing, since every call the admin UI makes goes
// through fetch().
const (
	xhrHeader = "X-Requested-With"
	xhrValue  = "XMLHttpRequest"
)

// requireXHR rejects a mutating /admin/api/* request that does not carry the
// xhrHeader. Reads are exempt: a cross-site GET can be forged just as
// easily, but it cannot change anything, and the attacker cannot read the
// answer either.
func requireXHR() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
			c.Next()
			return
		}
		if c.GetHeader(xhrHeader) != xhrValue {
			fail(c, http.StatusForbidden, "Missing "+xhrHeader+": "+xhrValue+" header.")
			return
		}
		c.Next()
	}
}
