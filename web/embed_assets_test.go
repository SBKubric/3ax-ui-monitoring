package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// assetRef matches every /admin/assets/<file> a page asks the browser to load.
var assetRef = regexp.MustCompile(`/admin/assets/([A-Za-z0-9._-]+)`)

// TestEveryReferencedAssetIsEmbedded ties the pages to the vendored files.
// A page that asks for an asset which is not embedded answers 404 in the
// browser, and a missing library is not a cosmetic failure here: ant-design-vue
// extends dayjs with seven plugins as it loads, so one 404 throws during
// startup and every page renders blank. That break is invisible to a Go test
// which only checks the page returns 200, so it is checked here instead.
func TestEveryReferencedAssetIsEmbedded(t *testing.T) {
	pages, err := fs.Glob(HTML, "*.html")
	if err != nil {
		t.Fatalf("list pages: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("no page templates are embedded")
	}

	seen := map[string]bool{}
	for _, page := range pages {
		body, err := fs.ReadFile(HTML, page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		for _, m := range assetRef.FindAllStringSubmatch(string(body), -1) {
			name := m[1]
			if seen[name] {
				continue
			}
			seen[name] = true
			if _, err := fs.Stat(Assets, name); err != nil {
				t.Errorf("%s loads /admin/assets/%s, which is not embedded", page, name)
			}
		}
	}
	if len(seen) == 0 {
		t.Error("no page references an embedded asset, which cannot be right")
	}
}

// TestAntDesignDayjsPluginsArePresent names the seven plugins explicitly, so
// that dropping one from web/assets fails here with the reason rather than in
// a browser with a blank page.
func TestAntDesignDayjsPluginsArePresent(t *testing.T) {
	for _, plugin := range []string{
		"advancedFormat", "customParseFormat", "localeData",
		"quarterOfYear", "weekOfYear", "weekYear", "weekday",
	} {
		name := "dayjs." + plugin + ".js"
		if _, err := fs.Stat(Assets, name); err != nil {
			t.Errorf("ant-design-vue extends dayjs with %s at load time, but %s is missing: %v", plugin, name, err)
		}
	}
}
