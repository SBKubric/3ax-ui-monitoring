package admin

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/web"
)

// assetMaxAge is how long a browser may cache the embedded Vue/antd bundles
// (spec §9.1: they are pinned UMD builds committed to the repo, so they only
// ever change with a new mon-server binary). An hour keeps a reload cheap
// without letting an upgraded binary serve yesterday's scripts for long.
const assetMaxAge = "public, max-age=3600"

// page returns the handler for one of the three signed-in pages (spec §9.2
// §9.3 §9.4). Each renders the same shell (layout.html: dark sidebar, the
// three menu items, the pending badge, the theme toggle) around that page's
// own Vue application.
func (h *Handler) page(name string) gin.HandlerFunc {
	return func(c *gin.Context) { h.render(c, name, nil) }
}

// render executes one page template with the shell data every page needs.
// It renders into a buffer first so that a template that fails halfway does
// not leave a half-written 200 on the wire; a failure becomes a 500 the
// operator can see in the log.
func (h *Handler) render(c *gin.Context, name string, extra gin.H) {
	tmpl := h.pages[name]
	if tmpl == nil {
		slog.Error("admin: no such page template", "page", name)
		c.String(http.StatusInternalServerError, "template missing")
		return
	}

	data := gin.H{
		"Page":     name,
		"Pending":  h.pendingCount(c),
		"PublicIP": h.publicIP(),
		"Listen":   h.listen(),
		"Version":  config.Version(),
	}
	for k, v := range extra {
		data[k] = v
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, web.RootTemplate, data); err != nil {
		slog.Error("admin: rendering a page failed", "page", name, "err", err)
		c.String(http.StatusInternalServerError, "template error")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}

// pendingCount is the number behind the Requests menu item's badge (spec
// §9.2). A database error shows as zero rather than failing the page: the
// badge is a hint, and an administrator who cannot open the registry at all
// because the count query failed is worse off than one who sees no badge.
func (h *Handler) pendingCount(c *gin.Context) int {
	if h.deps.Registry == nil {
		return 0
	}
	reqs, err := h.deps.Registry.PendingRequests(c.Request.Context())
	if err != nil {
		slog.Error("admin: counting pending registration requests failed", "err", err)
		return 0
	}
	return len(reqs)
}

// publicIP / listen are the bootstrap facts the sidebar and the "TLS &
// admin" tab show (spec §9.4). They tolerate a nil Cfg so a test can mount
// the UI without one.
func (h *Handler) publicIP() string {
	if h.deps.Cfg == nil {
		return ""
	}
	return h.deps.Cfg.PublicIP
}

func (h *Handler) listen() string {
	if h.deps.Cfg == nil {
		return ""
	}
	return h.deps.Cfg.Listen
}

// asset serves one embedded file from web/assets (spec §9.1: "лежат в
// web/assets/ и вшиваются в бинарник go:embed"). It is deliberately outside
// RequireSession: the login page needs Vue and Ant Design to render at all,
// and these are public third-party bundles with nothing of this install's in
// them. A request for a directory is a 404 rather than a listing.
func (h *Handler) asset(c *gin.Context) {
	name := strings.TrimPrefix(c.Param("filepath"), "/")
	if name == "" || strings.HasSuffix(name, "/") || strings.Contains(name, "..") {
		c.Status(http.StatusNotFound)
		return
	}
	data, err := web.Asset(name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Cache-Control", assetMaxAge)
	c.Data(http.StatusOK, web.ContentType(name), data)
}
