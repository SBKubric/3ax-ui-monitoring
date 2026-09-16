// Package web holds the admin UI and embeds it into the binary: the
// html/template pages of spec mon-server.md §9 and the vendored Vue 3, Ant
// Design Vue 4 and dayjs builds they load (web/assets/VENDOR.md).
//
// Nothing here is compiled at build time — the UMD builds are served as they
// are, so the Go build needs no Node (§9.1) — and nothing is read from disk at
// run time: mon-server serves the whole admin UI out of its own binary.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"sort"
)

//go:embed html
var htmlDir embed.FS

//go:embed assets
var assetsDir embed.FS

// HTML is the page templates, rooted at the html directory: "base.html",
// "login.html", "requests.html", "clients.html", "settings.html".
var HTML = mustSub(htmlDir, "html")

// Assets is the browser assets, rooted at the assets directory. internal/admin
// serves them under /admin/assets/.
var Assets = mustSub(assetsDir, "assets")

// AssetsVersion is a short digest of every asset. The pages hang it on their
// script and stylesheet tags, which makes each build's asset URLs new ones and
// lets the files themselves be served immutable.
var AssetsVersion = digest(Assets)

// mustSub roots an embedded FS at one directory. The directories are embedded
// literally above, so a failure here is a build that cannot happen.
func mustSub(fsys embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("web: embed " + dir + ": " + err.Error())
	}
	return sub
}

// digest hashes every file of fsys, names included, and returns the first
// sixteen hex characters. Walking in sorted order keeps it reproducible.
func digest(fsys fs.FS) string {
	var names []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		panic("web: walk assets: " + err.Error())
	}
	sort.Strings(names)

	sum := sha256.New()
	for _, name := range names {
		_, _ = io.WriteString(sum, name)
		f, err := fsys.Open(name)
		if err != nil {
			panic("web: open asset " + name + ": " + err.Error())
		}
		if _, err := io.Copy(sum, f); err != nil {
			_ = f.Close()
			panic("web: read asset " + name + ": " + err.Error())
		}
		_ = f.Close()
	}
	return hex.EncodeToString(sum.Sum(nil))[:16]
}
