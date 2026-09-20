// Package web holds the admin UI's static half — the html/template pages
// and the pinned Vue 3 / Ant Design Vue 4 / dayjs UMD bundles — and embeds
// all of it into the binary (spec §9.1: "вшиваются в бинарник go:embed ...
// Node в сборке не нужен"). It is a separate top-level package rather than
// part of internal/admin because spec §11 puts web/assets and web/html at
// the repository root, next to cmd/ and internal/, and because keeping the
// files and the Go code that serves them apart makes it obvious that
// nothing here executes: this package only hands out bytes.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"strings"
)

//go:embed assets html
var files embed.FS

// RootTemplate is the template every page is rendered through. The three
// signed-in pages share layout.html's shell (dark sidebar, three menu
// items, pending badge, theme toggle, per the spec's "вариант A"
// prototype); login.html defines a "layout" of its own because the login
// screen has no sidebar to put a menu in.
const RootTemplate = "layout"

// pageNames are the four surfaces spec §9 names. Each is parsed into its own
// template set (layout + that page) rather than one shared set, because each
// page defines the same block names — "content", "app" — and a single set
// would have them collide.
var pageNames = []string{"login", "requests", "clients", "settings"}

// MustParsePages parses every page template, keyed by page name. It panics
// on failure: the templates are embedded in the binary, so a parse error can
// only be a build-time mistake, and failing at start-up is far better than
// discovering it when an administrator opens that page.
func MustParsePages() map[string]*template.Template {
	out := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := parsePage(name)
		if err != nil {
			panic(fmt.Sprintf("web: parse page %s: %v", name, err))
		}
		out[name] = t
	}
	return out
}

// parsePage builds one page's template set: the page itself, plus the shared
// shell for every page that uses it.
func parsePage(name string) (*template.Template, error) {
	patterns := []string{"html/" + name + ".html"}
	if name != "login" {
		patterns = append(patterns, "html/layout.html")
	}
	return template.New(name).ParseFS(files, patterns...)
}

// Asset returns one file from web/assets by name (e.g. "antd.min.js"). It is
// the only way out of this package's embedded tree, and it reads assets
// only — a caller can never reach the templates through it.
func Asset(name string) ([]byte, error) {
	if strings.Contains(name, "..") {
		return nil, fs.ErrNotExist
	}
	return files.ReadFile(path.Join("assets", name))
}

// ContentType maps an asset's extension to the media type it must be served
// with. It is a tiny table rather than mime.TypeByExtension because the set
// of assets is fixed and committed, and because a container image without
// /etc/mime.types would otherwise serve JavaScript as text/plain, which
// every browser refuses to execute.
func ContentType(name string) string {
	switch path.Ext(name) {
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".json":
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}
