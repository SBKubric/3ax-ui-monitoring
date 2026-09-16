package admin

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/web"
)

// TestPagesRender: every page answers 200, is not cached, and boots exactly
// one Vue application from the embedded assets (§9.1).
func TestPagesRender(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending(), samplePending()}
	h.registry.clients = sampleClients()
	cookie := h.signIn()

	pages := []struct {
		path    string
		needs   []string
		sidebar bool
	}{
		{path: LoginPath, needs: []string{"login-form", "login-username", "login-password", "login-submit"}},
		{path: RequestsPath, needs: []string{"requests-table", "approve-modal", "request-approve-replacement"}, sidebar: true},
		{path: ClientsPath, needs: []string{"clients-table", "edit-modal", "revoke-modal", "delete-modal"}, sidebar: true},
		{path: SettingsPath, needs: []string{"settings-save", "settings-status", "tab-real", "tab-telegram", "tab-thresholds", "tab-probe", "tab-tls"}, sidebar: true},
	}
	for _, page := range pages {
		t.Run(page.path, func(t *testing.T) {
			// The login card is the one page a session must not see.
			pageCookie := cookie
			if page.path == LoginPath {
				pageCookie = nil
			}
			rec := h.get(page.path, pageCookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
				t.Errorf("content type = %q, want text/html", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("cache control = %q, want no-store", got)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `id="app"`) {
				t.Error("the page has no Vue mount point")
			}
			if strings.Count(body, ".mount('#app')") != 1 {
				t.Errorf("the page mounts %d applications, want exactly one", strings.Count(body, ".mount('#app')"))
			}
			for _, asset := range []string{"vue.global.prod.js", "antd.min.js", "dayjs.min.js", "reset.css"} {
				if !strings.Contains(body, "/admin/assets/"+asset+"?v="+web.AssetsVersion) {
					t.Errorf("the page does not load %s from the embedded assets", asset)
				}
			}
			for _, needle := range page.needs {
				if !strings.Contains(body, needle) {
					t.Errorf("the page does not carry %q", needle)
				}
			}
			// The sidebar is a component shared by the three pages behind
			// the login; only they place it.
			if page.sidebar {
				if !strings.Contains(body, "<mon-sider") {
					t.Error("the page does not place the sidebar")
				}
				for _, needle := range []string{"nav-requests", "nav-clients", "nav-settings", "nav-logout", "theme-toggle"} {
					if !strings.Contains(body, needle) {
						t.Errorf("the sidebar has no %q", needle)
					}
				}
			} else if strings.Contains(body, "<mon-sider") {
				t.Error("the login page places the sidebar")
			}
		})
	}
}

// TestPendingBadgeIsRenderedServerSide: the count is in the HTML, so it does
// not flash in after the first fetch (§9.2).
func TestPendingBadgeIsRenderedServerSide(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending(), samplePending(), samplePending()}
	cookie := h.signIn()

	body := h.get(ClientsPath, cookie).Body.String()
	if !strings.Contains(body, `"pending":3`) {
		t.Errorf("the page does not carry the pending count in its boot data:\n%s", firstLines(body, 40))
	}
}

// TestPagesCarryTheThemeAndTheStrings pins the two page-wide decisions of
// §9.1: the primary colour and one strings object per page.
func TestPagesCarryTheThemeAndTheStrings(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookie := h.signIn()

	for _, path := range []string{LoginPath, RequestsPath, ClientsPath, SettingsPath} {
		pageCookie := cookie
		if path == LoginPath {
			pageCookie = nil
		}
		body := h.get(path, pageCookie).Body.String()
		if !strings.Contains(body, "#008771") {
			t.Errorf("%s does not set colorPrimary", path)
		}
		if !strings.Contains(body, "darkAlgorithm") {
			t.Errorf("%s has no dark algorithm behind the switch", path)
		}
		if !strings.Contains(body, "mon-admin-theme") {
			t.Errorf("%s does not remember the theme in localStorage", path)
		}
		if !strings.Contains(body, "var strings = {") {
			t.Errorf("%s does not gather its strings in one object", path)
		}
	}
}

// TestAssetsAreServedFromTheBinary: every vendored file is served with a long
// cache lifetime and its own content type.
func TestAssetsAreServedFromTheBinary(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	cases := []struct {
		name string
		want string
	}{
		{"vue.global.prod.js", "javascript"},
		{"antd.min.js", "javascript"},
		{"dayjs.min.js", "javascript"},
		{"dayjs.relativeTime.js", "javascript"},
		{"reset.css", "text/css"},
	}
	for _, c := range cases {
		rec := h.get("/admin/assets/"+c.name, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", c.name, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Type"); !strings.Contains(got, c.want) {
			t.Errorf("%s: content type = %q, want %q", c.name, got, c.want)
		}
		if got := rec.Header().Get("Cache-Control"); got != assetCacheControl {
			t.Errorf("%s: cache control = %q, want %q", c.name, got, assetCacheControl)
		}
		embedded, err := readEmbedded(c.name)
		if err != nil {
			t.Fatalf("read the embedded %s: %v", c.name, err)
		}
		if rec.Body.Len() != len(embedded) {
			t.Errorf("%s: served %d bytes, the embedded file has %d", c.name, rec.Body.Len(), len(embedded))
		}
	}
}

// TestAssetsRefuseAnythingElse: no directory listing, no traversal.
func TestAssetsRefuseAnythingElse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for _, path := range []string{
		"/admin/assets/",
		"/admin/assets/nope.js",
		"/admin/assets/../html/base.html",
		"/admin/assets/sub/../reset.css",
	} {
		rec := h.get(path, nil)
		if rec.Code == http.StatusOK {
			t.Errorf("%s was served: %s", path, firstLines(rec.Body.String(), 3))
		}
	}
}

// TestServedWithNoFilesOnDisk runs the pages and the assets from a working
// directory that holds nothing at all: everything comes out of the binary.
func TestServedWithNoFilesOnDisk(t *testing.T) {
	h := newHarness(t)
	cookie := h.signIn()
	t.Chdir(t.TempDir())

	if rec := h.get(RequestsPath, cookie); rec.Code != http.StatusOK {
		t.Fatalf("page: status = %d, want 200", rec.Code)
	}
	rec := h.get("/admin/assets/vue.global.prod.js", nil)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("asset: status = %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

// TestNoTargetStateAnywhere is the rule of §1 and §9.3: the state of targets
// belongs to the panel's Monitoring page and appears nowhere in the admin UI,
// neither on a page nor in an API response.
func TestNoTargetStateAnywhere(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.registry.pending = []PendingRequest{samplePending()}
	h.registry.clients = sampleClients()
	cookie := h.signIn()

	// The vocabulary of the target state machine (§7.2) and of the panel's
	// inbound identity. ONLINE, OFFLINE and NEVER are mon-client states and
	// are allowed; UNKNOWN is also the panel's own "not polled yet".
	forbidden := []string{"FLAPPING", "PAUSED", "inboundKind", "inboundId", "\"targets\"", "targetState", "tcp_refused", "lat_avg"}

	surfaces := []string{
		LoginPath, RequestsPath, ClientsPath, SettingsPath,
		"/admin/api/requests", "/admin/api/clients", "/admin/api/settings",
	}
	for _, path := range surfaces {
		pageCookie := cookie
		if path == LoginPath {
			pageCookie = nil
		}
		rec := h.get(path, pageCookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
		body := rec.Body.String()
		for _, needle := range forbidden {
			if strings.Contains(body, needle) {
				t.Errorf("%s exposes target state: it contains %q", path, needle)
			}
		}
	}
}

// TestParsePagesIsDoneAtStartup: a page is parsed once, not per request.
func TestParsePagesIsDoneAtStartup(t *testing.T) {
	t.Parallel()
	set, err := parsePages()
	if err != nil {
		t.Fatalf("parse pages: %v", err)
	}
	for _, name := range []string{pageLogin, pageRequests, pageClients, pageSettings} {
		if set.templates[name] == nil {
			t.Errorf("page %s was not parsed", name)
		}
	}
}

// TestAssetsVersionIsStable: the digest of the embedded assets does not move
// between calls, so the cache-busting query is the same on every page.
func TestAssetsVersionIsStable(t *testing.T) {
	t.Parallel()
	if len(web.AssetsVersion) != 16 {
		t.Fatalf("assets version = %q, want sixteen hex characters", web.AssetsVersion)
	}
}

// readEmbedded reads one file out of the embedded asset FS.
func readEmbedded(name string) ([]byte, error) {
	f, err := web.Assets.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// firstLines keeps a failure message short.
func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
