package registry

import (
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Slug derives a mon-client id from its name (spec §6, mon-protocol.md §2.2):
// ASCII letters are lowercased, digits are kept, and every run of anything
// else — spaces, punctuation, and non-ASCII letters, which are not
// transliterated — collapses into a single dash. Leading and trailing dashes
// are dropped and the result is cut to 64 characters, the width of the id
// column.
//
// The result is therefore always a valid mon-client id, and a name with no
// ASCII letter or digit in it — punctuation only, or a word in an alphabet
// mon-server cannot spell — slugs to the empty string, which Approve refuses.
// The admin UI shows the slug under the name field, so the administrator sees
// that before approving.
func Slug(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	separator := false
	for _, ru := range name {
		switch {
		case ru >= 'a' && ru <= 'z', ru >= '0' && ru <= '9':
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			separator = false
			b.WriteRune(ru)
		case ru >= 'A' && ru <= 'Z':
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			separator = false
			b.WriteRune(ru - 'A' + 'a')
		default:
			separator = true
		}
	}
	slug := b.String()
	if len(slug) > maxMonClientIDLen {
		slug = strings.TrimRight(slug[:maxMonClientIDLen], "-")
	}
	return slug
}

// uniqueMonClientID returns base, or base with the first free -2, -3, …
// suffix, keeping the whole id inside the 64 character cap (spec §6). The
// caller holds the registry lock, so the id it gets is still free when it
// writes the row.
func uniqueMonClientID(tx *gorm.DB, base string) (string, error) {
	for n := 1; n <= 1000; n++ {
		candidate := base
		if n > 1 {
			suffix := "-" + strconv.Itoa(n)
			stem := base
			if len(stem)+len(suffix) > maxMonClientIDLen {
				stem = strings.TrimRight(stem[:maxMonClientIDLen-len(suffix)], "-")
			}
			candidate = stem + suffix
		}
		if !store.ValidMonClientID(candidate) {
			return "", ErrEmptyName
		}
		var taken int64
		if err := tx.Model(&store.MonClient{}).Where("id = ?", candidate).Count(&taken).Error; err != nil {
			return "", err
		}
		if taken == 0 {
			return candidate, nil
		}
	}
	return "", ErrNoFreeID
}

// normalisePaths validates the probe paths of a mon-client (spec §5, §6):
// duplicates collapse and anything that is not proxy or direct is refused. A
// nil slice — no paths field at all — means the default set; a set that is
// present but empty is refused, because a mon-client with no path to probe has
// nothing to do. The order of store.DefaultPaths is kept so two mon-clients
// with the same set store the same JSON.
func normalisePaths(paths []string) ([]string, error) {
	if paths == nil {
		return store.DefaultPaths(), nil
	}
	if len(paths) == 0 {
		return nil, ErrInvalidPaths
	}
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if !store.ValidPath(p) {
			return nil, ErrInvalidPaths
		}
		seen[p] = true
	}
	out := make([]string, 0, len(seen))
	for _, p := range store.DefaultPaths() {
		if seen[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, ErrInvalidPaths
	}
	return out, nil
}
