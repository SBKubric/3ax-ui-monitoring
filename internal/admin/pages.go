package admin

import (
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/web"
)

// Page names, which are also the template file names.
const (
	pageLogin    = "login"
	pageRequests = "requests"
	pageClients  = "clients"
	pageSettings = "settings"
)

// pageSet is the parsed pages. Each one is base.html plus its own file, so
// every page carries exactly one Vue application and the pages share a shell
// without a router (§9.1).
type pageSet struct {
	templates map[string]*template.Template
}

// parsePages parses the embedded templates once, at startup, so a broken page
// fails the process instead of the first request that reaches it.
func parsePages() (*pageSet, error) {
	set := &pageSet{templates: make(map[string]*template.Template, 4)}
	for _, name := range []string{pageLogin, pageRequests, pageClients, pageSettings} {
		t, err := template.New("base.html").ParseFS(web.HTML, "base.html", name+".html")
		if err != nil {
			return nil, fmt.Errorf("admin: parse page %s: %w", name, err)
		}
		set.templates[name] = t
	}
	return set, nil
}

// pageData is what a page template is executed with.
type pageData struct {
	// Title is the document title.
	Title string
	// Page names the active sidebar item.
	Page string
	// AssetsVersion is the cache-busting query of the asset tags.
	AssetsVersion string
	// Pending is the badge on the Requests menu item, rendered server side so
	// the count does not flash in after the first fetch (§9.2).
	Pending int
	// Server is the identity line under the brand.
	Server ServerInfo
	// Boot is handed to the Vue application as JSON.
	Boot bootData
}

// bootData is the JSON the page hands its Vue application. It holds no
// secrets: everything else the page needs it fetches from /admin/api/.
type bootData struct {
	Page             string `json:"page"`
	Pending          int    `json:"pending"`
	PublicIP         string `json:"publicIp"`
	Version          string `json:"version"`
	Next             string `json:"next,omitempty"`
	MaxLoginFailures int    `json:"maxLoginFailures"`
	LockoutMinutes   int    `json:"lockoutMinutes"`
	SessionHours     int    `json:"sessionHours"`
}

// render writes one page. Pages are never cached: they carry the session's
// view of the registry (§9.1).
func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	t, ok := s.pages.templates[name]
	if !ok {
		s.log.Error("unknown page", "page", name)
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	if err := t.Execute(w, data); err != nil {
		// The header is already out; log and let the truncated body speak.
		s.log.Error("rendering a page failed", "page", name, "error", err)
	}
}

// pageData assembles the shared part of every page.
func (s *Server) pageData(r *http.Request, name, title string) pageData {
	pending := 0
	if n, err := s.registry.PendingCount(r.Context()); err != nil {
		s.log.Error("counting registration requests failed", "error", err)
	} else {
		pending = n
	}
	return pageData{
		Title:         title,
		Page:          name,
		AssetsVersion: web.AssetsVersion,
		Pending:       pending,
		Server:        s.info,
		Boot: bootData{
			Page:             name,
			Pending:          pending,
			PublicIP:         s.info.PublicIP,
			Version:          s.info.Version,
			MaxLoginFailures: MaxLoginFailures,
			LockoutMinutes:   int(LockoutDuration.Minutes()),
			SessionHours:     int(SessionTTL.Hours()),
		},
	}
}

// loginPage renders the login card. A browser that already has a session is
// sent straight on.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok, err := s.session(r); err == nil && ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	data := pageData{
		Title:         "Sign in · mon-server",
		Page:          pageLogin,
		AssetsVersion: web.AssetsVersion,
		Server:        s.info,
		Boot: bootData{
			Page:             pageLogin,
			PublicIP:         s.info.PublicIP,
			Version:          s.info.Version,
			Next:             next,
			MaxLoginFailures: MaxLoginFailures,
			LockoutMinutes:   int(LockoutDuration.Minutes()),
			SessionHours:     int(SessionTTL.Hours()),
		},
	}
	s.render(w, pageLogin, data)
}

// requestsPage renders the registration requests page (§9.2).
func (s *Server) requestsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, pageRequests, s.pageData(r, pageRequests, "Requests · mon-server"))
}

// clientsPage renders the registry page (§9.3).
func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, pageClients, s.pageData(r, pageClients, "mon-clients · mon-server"))
}

// settingsPage renders the settings page (§9.4).
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, pageSettings, s.pageData(r, pageSettings, "Settings · mon-server"))
}

// assetCacheControl is how long a browser may keep an asset. The files only
// change with the binary and every tag carries AssetsVersion, so the URL of a
// new build is a new URL and the old answer can be kept forever.
const assetCacheControl = "public, max-age=31536000, immutable"

// serveAsset serves one embedded file from web/assets under /admin/assets/.
// Like the login page it needs no session: the login page loads from here.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	if name == "" || strings.HasSuffix(name, "/") || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	// Directories are not assets: only the files themselves are served, so
	// /admin/assets/ never lists what is inside the binary.
	clean := path.Clean(name)
	if clean != name {
		http.NotFound(w, r)
		return
	}
	f, err := web.Assets.Open(clean)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	info, err := f.Stat()
	_ = f.Close()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", assetCacheControl)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFileFS(w, r, web.Assets, clean)
}
