package registry

import (
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

func TestSlug(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "a plain name", in: "ams1", want: "ams1"},
		{name: "a space becomes a dash", in: "AMS 1", want: "ams-1"},
		{name: "uppercase is lowered", in: "Amsterdam", want: "amsterdam"},
		{name: "a run of spaces collapses", in: "Amsterdam    Edge", want: "amsterdam-edge"},
		{name: "surrounding blanks are dropped", in: "   AMS 1\t\n", want: "ams-1"},
		{name: "an underscore is punctuation", in: "AMS_1", want: "ams-1"},
		{name: "a dot is punctuation", in: "v1.2.3", want: "v1-2-3"},
		{name: "a run of punctuation collapses", in: "ams // 1", want: "ams-1"},
		{name: "leading and trailing dashes are trimmed", in: "--ams--1--", want: "ams-1"},
		{name: "an em dash is punctuation too", in: "ams—1", want: "ams-1"},
		{name: "an emoji is punctuation", in: "ams 1 \U0001F680", want: "ams-1"},
		{name: "only punctuation has no slug", in: "!!! ---", want: ""},
		{name: "only blanks have no slug", in: "   ", want: ""},
		{name: "an empty name has no slug", in: "", want: ""},
		{name: "a non ascii alphabet is not transliterated", in: "Москва", want: ""},
		{name: "non ascii letters act as separators", in: "Москва-1", want: "1"},
		{name: "an accent is a separator", in: "café 1", want: "caf-1"},
		{name: "digits are kept", in: "2024 edge 7", want: "2024-edge-7"},
		{
			name: "a two hundred character name is cut to sixty four",
			in:   strings.Repeat("a", 200),
			want: strings.Repeat("a", 64),
		},
		{
			name: "cutting never leaves a trailing dash",
			in:   strings.Repeat("abc ", 50),
			want: strings.TrimSuffix(strings.Repeat("abc-", 16), "-"),
		},
		{
			name: "a long name of punctuation and letters is cut cleanly",
			in:   strings.Repeat("Node! ", 40),
			want: strings.TrimSuffix(strings.Repeat("node-", 13), "-"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Slug(tc.in)
			if got != tc.want {
				t.Fatalf("Slug(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if len(got) > maxMonClientIDLen {
				t.Fatalf("Slug(%q) is %d characters, want at most %d", tc.in, len(got), maxMonClientIDLen)
			}
			if got != "" && !store.ValidMonClientID(got) {
				t.Fatalf("Slug(%q) = %q, which is not a valid mon-client id", tc.in, got)
			}
			if strings.HasPrefix(got, "-") || strings.HasSuffix(got, "-") {
				t.Fatalf("Slug(%q) = %q, want no leading or trailing dash", tc.in, got)
			}
		})
	}
}

func TestNormalisePaths(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
		err  error
	}{
		{name: "nothing chosen means both", in: nil, want: store.DefaultPaths()},
		{name: "proxy only", in: []string{"proxy"}, want: []string{"proxy"}},
		{name: "direct only", in: []string{"direct"}, want: []string{"direct"}},
		{name: "the order is canonical", in: []string{"direct", "proxy"}, want: []string{"proxy", "direct"}},
		{name: "duplicates collapse", in: []string{"proxy", "proxy"}, want: []string{"proxy"}},
		{name: "an explicitly empty set is refused", in: []string{}, err: ErrInvalidPaths},
		{name: "an unknown path is refused", in: []string{"tunnel"}, err: ErrInvalidPaths},
		{name: "a blank path is refused", in: []string{""}, err: ErrInvalidPaths},
		{name: "one good and one bad path is refused", in: []string{"proxy", "tunnel"}, err: ErrInvalidPaths},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalisePaths(tc.in)
			if tc.err != nil {
				if err == nil || !strings.Contains(err.Error(), tc.err.Error()) {
					t.Fatalf("normalisePaths(%v) = %v, %v, want %v", tc.in, got, err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalisePaths(%v): %v", tc.in, err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("normalisePaths(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
