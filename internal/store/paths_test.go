package store

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestValidPath pins the path grammar of spec §5.1 (protocol §4.2):
// direct | proxy | edge:<name> | inner:<name>, the name [a-z0-9-]{1,32}.
// "hops" is paths vocabulary, never a path.
func TestValidPath(t *testing.T) {
	long := strings.Repeat("a", 32)
	cases := map[string]bool{
		"direct":              true,
		"proxy":               true,
		"edge:ams-1":          true,
		"inner:core-1":        true,
		"inner:" + long:       true,
		"inner:" + long + "a": false,
		"hops":                false,
		"edge:":               false,
		"edge:AMS":            false,
		"edge:ams_1":          false,
		"middle:ams-1":        false,
		"edge:ams:1":          false,
		"":                    false,
		"Direct":              false,
	}
	for p, want := range cases {
		if got := ValidPath(p); got != want {
			t.Errorf("ValidPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestHopPath checks the one spelling of a hop's path, <role>:<name>, and
// that IsHopPath recognises exactly those.
func TestHopPath(t *testing.T) {
	if got := HopPath(HopRoleEdge, "ams-1"); got != "edge:ams-1" {
		t.Fatalf("HopPath(edge, ams-1) = %q", got)
	}
	if got := HopPath(HopRoleInner, "core-1"); got != "inner:core-1" {
		t.Fatalf("HopPath(inner, core-1) = %q", got)
	}
	for p, want := range map[string]bool{"edge:ams-1": true, "inner:core-1": true, "direct": false, "proxy": false, "hops": false, "edge:": false} {
		if got := IsHopPath(p); got != want {
			t.Errorf("IsHopPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestMigrate_RewritesProxyToHops is the paths vocabulary migration of
// decision #61 п. 3 (spec §3): a stored "proxy" becomes "hops" — on a panel
// without a chain it expands back into proxy, so nothing changes for such a
// box — and a list that already had both ends up with one "hops".
func TestMigrate_RewritesProxyToHops(t *testing.T) {
	s := openTestStore(t)
	seed := map[string][]string{
		"both":       {PathProxy, PathDirect},
		"proxy-only": {PathProxy},
		"direct":     {PathDirect},
		"already":    {PathDirect, PathHops},
		"dup":        {PathProxy, PathHops, "edge:ams-1"},
	}
	for id, paths := range seed {
		mc := &MonClient{Id: id, Name: id, Enabled: true}
		mc.SetPaths(paths)
		if err := s.DB.Create(mc).Error; err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	want := map[string][]string{
		"both":       {PathHops, PathDirect},
		"proxy-only": {PathHops},
		"direct":     {PathDirect},
		"already":    {PathDirect, PathHops},
		"dup":        {PathHops, "edge:ams-1"},
	}
	for id, w := range want {
		var got MonClient
		if err := s.DB.First(&got, "id = ?", id).Error; err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		if !slices.Equal(got.PathsList(), w) {
			t.Errorf("%s: paths = %v, want %v", id, got.PathsList(), w)
		}
	}

	// A second start finds nothing left to rewrite.
	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// TestMonClient_UnallocatedRoundTrip checks the column behind the admin
// UI's "no peer" tag (spec §3, §9.3): the pairs of this mon-client the
// panel's last ensure left without an AWG probe peer, each with its reason.
func TestMonClient_UnallocatedRoundTrip(t *testing.T) {
	s := openTestStore(t)
	mc := &MonClient{Id: "ams-1", Name: "ams-1", Enabled: true}
	mc.SetPaths(nil)
	if err := s.DB.Create(mc).Error; err != nil {
		t.Fatalf("create: %v", err)
	}

	var fresh MonClient
	if err := s.DB.First(&fresh, "id = ?", "ams-1").Error; err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := fresh.UnallocatedList(); len(got) != 0 {
		t.Fatalf("a new row has unallocated = %v, want none", got)
	}

	want := []UnallocatedPeer{{Path: "inner:core-1", Reason: UnallocatedLimit}, {Path: PathDirect, Reason: UnallocatedPoolExhausted}}
	fresh.SetUnallocated(want)
	if err := s.DB.Model(&MonClient{}).Where("id = ?", "ams-1").Update("unallocated", fresh.Unallocated).Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	var back MonClient
	if err := s.DB.First(&back, "id = ?", "ams-1").Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := back.UnallocatedList(); !slices.Equal(got, want) {
		t.Fatalf("unallocated = %v, want %v", got, want)
	}

	back.SetUnallocated(nil)
	if back.Unallocated != "[]" {
		t.Fatalf("SetUnallocated(nil) = %q, want []", back.Unallocated)
	}
}

// TestTargets_HopPathFitsEveryPathColumn checks the longest path the
// grammar allows (inner: + a 32-character name) goes into targets,
// stats_buckets and probe_seen and comes back whole: the path columns are
// not cut to the old direct/proxy width (spec §3).
func TestTargets_HopPathFitsEveryPathColumn(t *testing.T) {
	s := openTestStore(t)
	path := "inner:" + strings.Repeat("n", 32)

	tg := Target{MonClientId: "ams-1", InboundKind: InboundKindXray, InboundId: 12, Path: path, State: TargetUnknown}
	if err := s.DB.Create(&tg).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}
	b := StatsBucket{MonClientId: "ams-1", InboundKind: InboundKindXray, InboundId: 12, Path: path, BucketStart: 300_000}
	if err := s.DB.Create(&b).Error; err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	ps := ProbeSeen{MonClientId: "ams-1", InboundKind: InboundKindXray, InboundId: 12, Path: path, SeenAt: 1}
	if err := s.DB.Create(&ps).Error; err != nil {
		t.Fatalf("create probe_seen: %v", err)
	}

	var gotT Target
	var gotB StatsBucket
	var gotP ProbeSeen
	s.DB.First(&gotT, tg.Id)
	s.DB.First(&gotB, b.Id)
	s.DB.First(&gotP, ps.Id)
	for name, got := range map[string]string{"targets": gotT.Path, "stats_buckets": gotB.Path, "probe_seen": gotP.Path} {
		if got != path {
			t.Errorf("%s.path = %q, want %q", name, got, path)
		}
	}
	// SQLite would store the long value in a varchar(16) as well, so the
	// round trip alone cannot catch the width coming back; the tags can.
	for name, typ := range map[string]reflect.Type{
		"Target": reflect.TypeOf(Target{}), "StatsBucket": reflect.TypeOf(StatsBucket{}), "ProbeSeen": reflect.TypeOf(ProbeSeen{}),
	} {
		f, _ := typ.FieldByName("Path")
		if strings.Contains(f.Tag.Get("gorm"), "size:") {
			t.Errorf("%s.Path is sized (%s), want an unbounded column", name, f.Tag.Get("gorm"))
		}
	}
}
