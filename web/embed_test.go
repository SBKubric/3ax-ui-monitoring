package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// assetRef finds every /admin/assets/<file> a page template loads.
var assetRef = regexp.MustCompile(`/admin/assets/([A-Za-z0-9._-]+)`)

// TestPagesParse: every page template parses and renders through the shell
// (spec §9.1). admin.New panics on a failure here, so this test is what
// turns a broken template into a red test rather than a start-up panic in
// production.
func TestPagesParse(t *testing.T) {
	pages := MustParsePages()
	for _, name := range pageNames {
		if pages[name] == nil {
			t.Fatalf("no template for page %q", name)
		}
		if pages[name].Lookup(RootTemplate) == nil {
			t.Fatalf("page %q defines no %q template", name, RootTemplate)
		}
	}
}

// TestEveryReferencedAssetIsEmbedded: a page that loads a script which is
// not in web/assets would render a blank screen with a 404 in the console
// and nothing in mon-server's log. Checking the reference against the embed
// catches that typo at test time instead.
func TestEveryReferencedAssetIsEmbedded(t *testing.T) {
	entries, err := fs.ReadDir(files, "html")
	if err != nil {
		t.Fatalf("read html dir: %v", err)
	}
	seen := 0
	for _, e := range entries {
		raw, err := files.ReadFile("html/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range assetRef.FindAllStringSubmatch(string(raw), -1) {
			seen++
			if _, err := Asset(m[1]); err != nil {
				t.Fatalf("%s loads /admin/assets/%s, which is not embedded: %v", e.Name(), m[1], err)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no asset references found in the templates at all")
	}
}

// TestAsset_RefusesTraversal: Asset is the only way out of the embedded
// tree, so it must not be a way into the templates.
func TestAsset_RefusesTraversal(t *testing.T) {
	if _, err := Asset("../html/layout.html"); err == nil {
		t.Fatal("Asset served a file outside web/assets")
	}
}

// TestContentType covers the two media types that matter: a browser refuses
// to execute JavaScript served as anything else.
func TestContentType(t *testing.T) {
	if got := ContentType("app.js"); !strings.HasPrefix(got, "application/javascript") {
		t.Fatalf("ContentType(app.js) = %q", got)
	}
	if got := ContentType("app.css"); !strings.HasPrefix(got, "text/css") {
		t.Fatalf("ContentType(app.css) = %q", got)
	}
}
