package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// registerClient approves a mon-client named name and returns its id and the
// token it was issued.
func registerClient(t *testing.T, reg *Registry, fake *clock.Fake, ip, name string) (string, string) {
	t.Helper()
	res := submit(t, reg, ip, "7K3F9Q")
	out := approve(t, reg, res.RequestID, ApproveInput{Name: name, Region: "eu"})
	token := issuedToken(t, reg, res.RequestID)
	fake.Advance(61 * time.Second)
	return out.MonClientID, token
}

// addTarget writes one target of a mon-client in the given state.
func addTarget(t *testing.T, st *store.Store, monClientID string, inboundID int64, path, state string) {
	t.Helper()
	row := store.Target{
		MonClientID: monClientID,
		InboundKind: store.InboundKindXray,
		InboundID:   inboundID,
		Path:        path,
		State:       state,
		Since:       clock.MS(testTime),
	}
	if err := st.DB().Create(&row).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}
}

// outboxEvents reads back everything the outbox holds, oldest first.
func outboxEvents(t *testing.T, st *store.Store) []panel.Event {
	t.Helper()
	var rows []store.EventOutbox
	if err := st.DB().Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	out := make([]panel.Event, 0, len(rows))
	for _, row := range rows {
		ev, err := events.UnmarshalEvent(row.Payload)
		if err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestListAndGet(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	ctx := context.Background()
	registerClient(t, reg, fake, "203.0.113.1", "FRA 1")
	registerClient(t, reg, fake, "203.0.113.2", "AMS 1")

	list, err := reg.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].ID != "ams-1" || list[1].ID != "fra-1" {
		t.Fatalf("List = %+v, want ams-1 then fra-1", list)
	}
	if !list[0].HasToken || !list[0].Enabled || list[0].State != store.ClientStateNever {
		t.Errorf("entry = %+v, want an enabled, never seen mon-client holding a token", list[0])
	}
	if strings.Join(list[0].Paths, ",") != "proxy,direct" {
		t.Errorf("paths = %v, want them decoded", list[0].Paths)
	}

	got, err := reg.Get(ctx, "ams-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "AMS 1" || got.Region != "eu" {
		t.Errorf("Get = %+v, want the approved name and region", got)
	}
	if _, err := reg.Get(ctx, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Get of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestUpdateChangesEverythingButTheID(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	id, token := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")

	if err := reg.Update(ctx, id, "Amsterdam edge", "eu-west", []string{"direct"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	row := clientRow(t, st, id)
	if row.ID != "ams-1" {
		t.Errorf("id = %q, want it unchanged by a rename", row.ID)
	}
	if row.Name != "Amsterdam edge" || row.Region != "eu-west" {
		t.Errorf("name/region = %q/%q, want the new ones", row.Name, row.Region)
	}
	if paths, _ := store.DecodePaths(row.Paths); strings.Join(paths, ",") != "direct" {
		t.Errorf("paths = %v, want [direct]", paths)
	}
	if row.TokenHash != store.HashToken(token) {
		t.Error("an edit must not touch the token")
	}

	if err := reg.Update(ctx, id, "  ", "eu", nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("Update with a blank name = %v, want ErrEmptyName", err)
	}
	if err := reg.Update(ctx, id, "AMS 1", "eu", []string{"tunnel"}); !errors.Is(err, ErrInvalidPaths) {
		t.Errorf("Update with an unknown path = %v, want ErrInvalidPaths", err)
	}
	if err := reg.Update(ctx, id, "AMS 1", "eu", []string{}); !errors.Is(err, ErrInvalidPaths) {
		t.Errorf("Update with no path = %v, want ErrInvalidPaths", err)
	}
	if err := reg.Update(ctx, "nope", "AMS 1", "eu", nil); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Update of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestRevokeKeepsTheRowAndDropsTheToken(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	id, token := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")
	if err := st.DB().Model(&store.MonClient{}).Where("id = ?", id).Update("state", store.ClientStateOnline).Error; err != nil {
		t.Fatalf("bring the mon-client online: %v", err)
	}

	if err := reg.Revoke(ctx, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	row := clientRow(t, st, id)
	if row.TokenHash != "" {
		t.Errorf("token_hash = %q, want it cleared", row.TokenHash)
	}
	if row.State != store.ClientStateOffline {
		t.Errorf("state = %q, want %q", row.State, store.ClientStateOffline)
	}
	if _, err := reg.AuthenticateClient(ctx, token); !errors.Is(err, api.ErrTokenRevoked) {
		t.Errorf("the revoked token still authenticates: %v", err)
	}
	got, err := reg.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.HasToken {
		t.Error("the admin UI is told the mon-client still holds a token")
	}
	if err := reg.Revoke(ctx, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Revoke of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestDisableMovesTargetsToUnknownAndFilesOneEventEach(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	id, _ := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")
	other, _ := registerClient(t, reg, fake, "203.0.113.2", "FRA 1")

	addTarget(t, st, id, 7, store.PathProxy, store.TargetUp)
	addTarget(t, st, id, 7, store.PathDirect, store.TargetDown)
	addTarget(t, st, id, 9, store.PathDirect, store.TargetUnknown)
	addTarget(t, st, other, 7, store.PathProxy, store.TargetUp)
	now := clock.MS(fake.Now())

	if err := reg.Disable(ctx, id); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if clientRow(t, st, id).Enabled {
		t.Error("the mon-client is still enabled")
	}
	var targets []store.Target
	if err := st.DB().Where("mon_client_id = ?", id).Order("id ASC").Find(&targets).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	for _, target := range targets {
		if target.State != store.TargetUnknown {
			t.Errorf("target %d/%s = %q, want %q", target.InboundID, target.Path, target.State, store.TargetUnknown)
		}
	}
	if targets[0].Reason != panel.ReasonMonClientDisabled || targets[0].Since != now {
		t.Errorf("target = %+v, want reason %q at %d", targets[0], panel.ReasonMonClientDisabled, now)
	}

	// Another mon-client's targets are none of this one's business.
	var untouched store.Target
	if err := st.DB().Where("mon_client_id = ?", other).Take(&untouched).Error; err != nil {
		t.Fatalf("read the other mon-client's target: %v", err)
	}
	if untouched.State != store.TargetUp {
		t.Errorf("the other mon-client's target moved to %q", untouched.State)
	}

	evs := outboxEvents(t, st)
	if len(evs) != 2 {
		t.Fatalf("filed %d events, want one per target that actually moved", len(evs))
	}
	for _, ev := range evs {
		if ev.Kind != panel.EventKindTarget || ev.MonClientID != id {
			t.Errorf("event = %+v, want a target event of %s", ev, id)
		}
		if ev.To != store.TargetUnknown || ev.Reason != panel.ReasonMonClientDisabled {
			t.Errorf("event = %+v, want a move to UNKNOWN with reason %q", ev, panel.ReasonMonClientDisabled)
		}
		if ev.TS != now {
			t.Errorf("event ts = %d, want %d", ev.TS, now)
		}
	}
	if evs[0].From != store.TargetUp || evs[1].From != store.TargetDown {
		t.Errorf("events came from %q and %q, want the states the targets were in", evs[0].From, evs[1].From)
	}

	if err := reg.Disable(ctx, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Disable of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestEnableLeavesTargetsUnknown(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	id, _ := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")
	addTarget(t, st, id, 7, store.PathProxy, store.TargetUp)

	if err := reg.Disable(ctx, id); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := reg.Enable(ctx, id); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !clientRow(t, st, id).Enabled {
		t.Error("the mon-client is still disabled")
	}
	var target store.Target
	if err := st.DB().Where("mon_client_id = ?", id).Take(&target).Error; err != nil {
		t.Fatalf("read target: %v", err)
	}
	if target.State != store.TargetUnknown {
		t.Errorf("target = %q, want it to stay %q until a result arrives", target.State, store.TargetUnknown)
	}
	if got := len(outboxEvents(t, st)); got != 1 {
		t.Errorf("the outbox holds %d events, want only the one Disable filed", got)
	}
	if err := reg.Enable(ctx, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Enable of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestDeleteRemovesTheMonClientItsTargetsAndItsConfig(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	id, _ := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")
	other, _ := registerClient(t, reg, fake, "203.0.113.2", "FRA 1")

	for _, mc := range []string{id, other} {
		addTarget(t, st, mc, 7, store.PathProxy, store.TargetUp)
		cfg := store.ClientConfig{MonClientID: mc, Revision: "abc123", Document: "{}", BuiltAt: clock.MS(testTime)}
		if err := st.DB().Create(&cfg).Error; err != nil {
			t.Fatalf("create client config: %v", err)
		}
	}

	if err := reg.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := reg.Get(ctx, id); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("the mon-client is still there: %v", err)
	}
	for _, table := range []any{&store.Target{}, &store.ClientConfig{}} {
		var count int64
		if err := st.DB().Model(table).Where("mon_client_id = ?", id).Count(&count).Error; err != nil {
			t.Fatalf("count rows: %v", err)
		}
		if count != 0 {
			t.Errorf("%T left %d rows behind", table, count)
		}
	}
	var kept int64
	if err := st.DB().Model(&store.Target{}).Where("mon_client_id = ?", other).Count(&kept).Error; err != nil {
		t.Fatalf("count the other mon-client's targets: %v", err)
	}
	if kept != 1 {
		t.Errorf("the other mon-client kept %d targets, want 1", kept)
	}
	if err := reg.Delete(ctx, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Errorf("Delete of an unknown id = %v, want ErrMonClientNotFound", err)
	}
}

func TestSnapshotCarriesEveryMonClient(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()
	live, _ := registerClient(t, reg, fake, "203.0.113.1", "AMS 1")
	off, _ := registerClient(t, reg, fake, "203.0.113.2", "FRA 1")
	registerClient(t, reg, fake, "203.0.113.3", "MSK 1")

	beat := clock.MS(fake.Now())
	err := st.DB().Model(&store.MonClient{}).Where("id = ?", live).
		Updates(map[string]any{"state": store.ClientStateOnline, "last_heartbeat": beat}).Error
	if err != nil {
		t.Fatalf("bring the mon-client online: %v", err)
	}
	if err := reg.Disable(ctx, off); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	got, err := reg.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("snapshot carries %d mon-clients, want 3: the disabled and the never seen are in it", len(got))
	}
	want := map[string]panel.MonClientSnapshot{
		"ams-1": {ID: "ams-1", Name: "AMS 1", Region: "eu", State: store.ClientStateOnline, LastHeartbeat: beat},
		"fra-1": {ID: "fra-1", Name: "FRA 1", Region: "eu", State: store.ClientStateNever},
		"msk-1": {ID: "msk-1", Name: "MSK 1", Region: "eu", State: store.ClientStateNever},
	}
	for _, entry := range got {
		if entry != want[entry.ID] {
			t.Errorf("snapshot entry = %+v, want %+v", entry, want[entry.ID])
		}
	}
}
