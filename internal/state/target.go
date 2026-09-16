package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// TargetKey names one target of one mon-client: an inbound of the real server
// reached over one path (CONTEXT.md, spec §7.2). It is the identity of a row
// of the targets table, without the mon-client id the caller already knows.
type TargetKey struct {
	InboundKind string
	InboundID   int64
	Path        string
}

// String renders the key the way a tunnel probe and a Telegram message name a
// target, "kind:inboundId:path".
func (k TargetKey) String() string { return events.TargetKey(k.InboundKind, k.InboundID, k.Path) }

// keyOf is the TargetKey of a stored row.
func keyOf(t *store.Target) TargetKey {
	return TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundID, Path: t.Path}
}

// transition is one entry of the flap window stored in Target.Transitions: the
// receive time of an UP↔DOWN transition, the state it went to and the reason
// it carried. The window is what spec §7.2 counts for FLAPPING, and it is
// trimmed to flapMin on every append so it cannot grow without bound.
//
// The entries also record which state the target is really in while it is held
// in FLAPPING: the stored state column reads FLAPPING, the last entry of the
// window is the state the results are actually describing, and that is what
// the target settles on when the hold expires.
type transition struct {
	TS     int64  `json:"ts"`
	To     string `json:"to"`
	Reason string `json:"reason,omitempty"`
}

// decodeTransitions parses the stored window. An empty or unreadable column
// yields an empty window: a broken flap history must not stop the state
// machine, it only costs one flap detection.
func (m *Machine) decodeTransitions(t *store.Target) []transition {
	if t.Transitions == "" {
		return nil
	}
	var window []transition
	if err := json.Unmarshal([]byte(t.Transitions), &window); err != nil {
		m.log.Warn("unreadable transition window, starting a new one",
			"monClientId", t.MonClientID, "target", keyOf(t).String(), "error", err)
		return nil
	}
	return window
}

// encodeTransitions stores the window back, writing the empty window as an
// empty column.
func encodeTransitions(window []transition) (string, error) {
	if len(window) == 0 {
		return "", nil
	}
	b, err := json.Marshal(window)
	if err != nil {
		return "", fmt.Errorf("state: encode transitions: %w", err)
	}
	return string(b), nil
}

// trimWindow drops the transitions older than the flap window, so that
// FLAPPING counts only what happened within flapMin of now.
func trimWindow(window []transition, notBefore int64) []transition {
	out := window[:0]
	for _, tr := range window {
		if tr.TS >= notBefore {
			out = append(out, tr)
		}
	}
	return out
}

// shadowState is the state a flapping target is really in: the target of the
// last recorded transition. It is the empty string when the window is empty.
func shadowState(window []transition) (state, reason string) {
	if len(window) == 0 {
		return "", ""
	}
	last := window[len(window)-1]
	return last.To, last.Reason
}

// resultOutcome is one probe result reduced to what the state machine needs.
type resultOutcome struct {
	ok     bool
	reason string
}

// applyResult runs one result of the live cycle through the state machine of
// spec §7.2 and returns the transitions it produced. now is mon-server's
// receive time; the mon-client's own clock never reaches this function.
//
// The row is updated in place and is the caller's to save.
func (m *Machine) applyResult(t *store.Target, out resultOutcome, now int64, th thresholds) []pendingEvent {
	var evs []pendingEvent

	// A FLAPPING target that has been quiet for flapHoldMin settles first, on
	// the state the results have really been describing; the result in hand is
	// then applied to that settled state.
	if t.State == store.TargetFlapping && t.FlappingUntil > 0 && now >= t.FlappingUntil {
		evs = append(evs, m.settleFlapping(t, now)...)
	}

	first := t.LastResultAt == 0
	if out.ok {
		t.ConsecutiveOK++
		t.ConsecutiveFail = 0
	} else {
		t.ConsecutiveFail++
		t.ConsecutiveOK = 0
	}
	t.LastResultAt = now

	// While FLAPPING the thresholds are compared against the shadow state, not
	// against the FLAPPING label, so the oscillation keeps being counted.
	window := trimWindow(m.decodeTransitions(t), now-th.flapWindowMS)
	cur := t.State
	if cur == store.TargetFlapping {
		if shadow, _ := shadowState(window); shadow != "" {
			cur = shadow
		} else {
			cur = store.TargetUnknown
		}
	}

	var next, reason string
	switch {
	case out.ok && cur != store.TargetUp && (first || t.ConsecutiveOK >= th.upAfter):
		// upAfter consecutive successes, or the very first result a target
		// ever gets: a target that answers straight away starts UP instead of
		// spending a cycle in UNKNOWN (spec §7.2, "стартовое — первый успех").
		next, reason = store.TargetUp, panel.ReasonRecovered
	case !out.ok && cur != store.TargetDown && t.ConsecutiveFail >= th.downAfter:
		// downAfter consecutive failures while heartbeats keep arriving. The
		// reason is the mon-client's diagnosis of the probe.
		next, reason = store.TargetDown, out.reason
	}
	if next == "" {
		if err := m.storeWindow(t, window); err != nil {
			m.log.Warn("could not store the transition window", "monClientId", t.MonClientID, "target", keyOf(t).String(), "error", err)
		}
		return evs
	}

	// Only UP↔DOWN oscillation counts towards flapping: leaving UNKNOWN or
	// PAUSED is a target starting up, not a target misbehaving.
	if isUpDown(cur) && isUpDown(next) {
		window = trimWindow(append(window, transition{TS: now, To: next, Reason: reason}), now-th.flapWindowMS)
	}
	if err := m.storeWindow(t, window); err != nil {
		m.log.Warn("could not store the transition window", "monClientId", t.MonClientID, "target", keyOf(t).String(), "error", err)
	}

	switch {
	case t.State == store.TargetFlapping:
		// A transition inside FLAPPING: filed so the panel's feed is complete,
		// quiet so the owner hears one message on entering and one on leaving,
		// and it restarts the quiet period.
		t.FlappingUntil = now + th.flapHoldMS
		evs = append(evs, quietEvent(m.targetEvent(t, now, cur, next, reason)))
	case len(window) >= th.flapN:
		// The transition that completes flapN transitions within flapMin is
		// announced as the entry into FLAPPING rather than as itself.
		evs = append(evs, loudEvent(m.targetEvent(t, now, t.State, store.TargetFlapping, panel.ReasonFlapping)))
		t.State = store.TargetFlapping
		t.Since = now
		t.Reason = panel.ReasonFlapping
		t.FlappingUntil = now + th.flapHoldMS
	default:
		evs = append(evs, loudEvent(m.targetEvent(t, now, t.State, next, reason)))
		t.State = next
		t.Since = now
		t.Reason = reason
		t.FlappingUntil = 0
	}
	return evs
}

// settleFlapping leaves FLAPPING after flapHoldMin without a transition, onto
// the state the results have really been describing (spec §7.2). The window is
// cleared: the quiet period is the verdict that the oscillation is over, so
// the next one is counted from scratch.
func (m *Machine) settleFlapping(t *store.Target, now int64) []pendingEvent {
	settled, reason := shadowState(m.decodeTransitions(t))
	if settled == "" {
		settled, reason = store.TargetUnknown, ""
	}
	if settled == store.TargetUp {
		reason = panel.ReasonRecovered
	}
	ev := loudEvent(m.targetEvent(t, now, store.TargetFlapping, settled, reason))
	t.State = settled
	t.Since = now
	t.Reason = reason
	t.FlappingUntil = 0
	t.Transitions = ""
	return []pendingEvent{ev}
}

// storeWindow encodes the window back into the row.
func (m *Machine) storeWindow(t *store.Target, window []transition) error {
	raw, err := encodeTransitions(window)
	if err != nil {
		return err
	}
	t.Transitions = raw
	return nil
}

// isUpDown reports whether a state takes part in flap counting.
func isUpDown(s string) bool { return s == store.TargetUp || s == store.TargetDown }

// targetEvent builds the contract event of one target transition (contract
// §4.6), stamped with mon-server's receive time.
func (m *Machine) targetEvent(t *store.Target, now int64, from, to, reason string) panel.Event {
	return events.Target(now, t.MonClientID, t.InboundKind, t.InboundID, t.Path, from, to, reason)
}

// Pause moves one target to PAUSED: its inbound was disabled in the panel or
// disappeared from GET /probe/configs, so its results stop meaning anything
// (spec §7.2, §4 step 3). reason defaults to config_disabled. The transition
// is filed as an event and never announced.
//
// The panel poll calls it when the inbound set changes.
func (m *Machine) Pause(ctx context.Context, monClientID, inboundKind string, inboundID int64, path, reason string) error {
	if reason == "" {
		reason = panel.ReasonConfigDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	row, err := m.loadTarget(ctx, monClientID, TargetKey{InboundKind: inboundKind, InboundID: inboundID, Path: path})
	if err != nil || row == nil {
		return err
	}
	evs := m.pause(row, m.nowMS(), reason)
	if len(evs) == 0 {
		return nil
	}
	if err := m.saveTarget(ctx, row); err != nil {
		return err
	}
	return m.file(ctx, evs)
}

// Resume is the reverse of Pause: the configuration lists the target again, so
// it goes back to UNKNOWN with config_enabled and waits for a result (spec
// §7.2). A target that is not paused is left alone.
func (m *Machine) Resume(ctx context.Context, monClientID, inboundKind string, inboundID int64, path, reason string) error {
	if reason == "" {
		reason = panel.ReasonConfigEnabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	key := TargetKey{InboundKind: inboundKind, InboundID: inboundID, Path: path}
	row, err := m.loadTarget(ctx, monClientID, key)
	if err != nil {
		return err
	}
	if row == nil {
		if _, err := m.createTarget(ctx, monClientID, key, m.nowMS()); err != nil {
			return err
		}
		return nil
	}
	evs := m.resume(row, m.nowMS(), reason)
	if len(evs) == 0 {
		return nil
	}
	if err := m.saveTarget(ctx, row); err != nil {
		return err
	}
	return m.file(ctx, evs)
}

// pause applies PAUSED to a loaded row, returning the event it produced.
func (m *Machine) pause(t *store.Target, now int64, reason string) []pendingEvent {
	if t.State == store.TargetPaused {
		return nil
	}
	ev := quietEvent(m.targetEvent(t, now, t.State, store.TargetPaused, reason))
	t.State = store.TargetPaused
	t.Since = now
	t.Reason = reason
	t.ConsecutiveOK = 0
	t.ConsecutiveFail = 0
	t.Transitions = ""
	t.FlappingUntil = 0
	return []pendingEvent{ev}
}

// resume applies the return to UNKNOWN to a loaded row. The result history is
// cleared with it: a target that comes back from PAUSED starts over, so its
// first successful probe brings it straight to UP the way a new one does.
func (m *Machine) resume(t *store.Target, now int64, reason string) []pendingEvent {
	if t.State != store.TargetPaused {
		return nil
	}
	ev := quietEvent(m.targetEvent(t, now, store.TargetPaused, store.TargetUnknown, reason))
	t.State = store.TargetUnknown
	t.Since = now
	t.Reason = reason
	t.ConsecutiveOK = 0
	t.ConsecutiveFail = 0
	t.Transitions = ""
	t.FlappingUntil = 0
	t.LastResultAt = 0
	return []pendingEvent{ev}
}

// SyncTargets makes the targets table match the set of targets one mon-client
// is configured to probe: rows that are missing are created in UNKNOWN, rows
// that are no longer wanted are moved to PAUSED with config_disabled, and rows
// that are wanted again come back to UNKNOWN with config_enabled.
//
// It is called by the panel poll after it rebuilds the client configs, which
// is when the inbound set can change (spec §4 step 3), and by the registry
// when a mon-client is approved or its paths are edited (§6). Nothing else
// creates target rows: a heartbeat naming a target that is not in the current
// configuration is discarded rather than allowed to invent one (§7.1).
//
// A newly created row files no event. It has no state to transition from, and
// the contract's from/to are target states (§4.6); the panel learns the target
// exists from its first real transition and from its statistics.
func (m *Machine) SyncTargets(ctx context.Context, monClientID string, wanted []TargetKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rows, err := m.loadTargets(ctx, monClientID)
	if err != nil {
		return err
	}
	byKey := make(map[TargetKey]*store.Target, len(rows))
	for i := range rows {
		byKey[keyOf(&rows[i])] = &rows[i]
	}
	wantedSet := make(map[TargetKey]struct{}, len(wanted))
	now := m.nowMS()

	var evs []pendingEvent
	for _, key := range wanted {
		wantedSet[key] = struct{}{}
		row, ok := byKey[key]
		if !ok {
			if _, err := m.createTarget(ctx, monClientID, key, now); err != nil {
				return err
			}
			continue
		}
		changed := m.resume(row, now, panel.ReasonConfigEnabled)
		if len(changed) == 0 {
			continue
		}
		if err := m.saveTarget(ctx, row); err != nil {
			return err
		}
		evs = append(evs, changed...)
	}
	for key, row := range byKey {
		if _, ok := wantedSet[key]; ok {
			continue
		}
		changed := m.pause(row, now, panel.ReasonConfigDisabled)
		if len(changed) == 0 {
			continue
		}
		if err := m.saveTarget(ctx, row); err != nil {
			return err
		}
		evs = append(evs, changed...)
	}
	return m.file(ctx, evs)
}

// ResetToUnknown moves every target of one mon-client to UNKNOWN and returns
// how many it moved. It is what happens when the mon-client itself stops being
// a witness: the liveness job calls it with mon_client_offline (spec §7.3) and
// the registry calls it with mon_client_disabled when an administrator
// disables a mon-client (§6). The transitions are filed as events and never
// announced: the mon-client's own event is the one the owner hears.
//
// Paused targets are left alone — they are paused by configuration, not by the
// mon-client's silence.
func (m *Machine) ResetToUnknown(ctx context.Context, monClientID, reason string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resetToUnknown(ctx, monClientID, reason)
}

// resetToUnknown is ResetToUnknown with the lock already held.
func (m *Machine) resetToUnknown(ctx context.Context, monClientID, reason string) (int, error) {
	rows, err := m.loadTargets(ctx, monClientID)
	if err != nil {
		return 0, err
	}
	now := m.nowMS()
	var evs []pendingEvent
	moved := 0
	for i := range rows {
		row := &rows[i]
		if row.State == store.TargetPaused || row.State == store.TargetUnknown {
			continue
		}
		evs = append(evs, quietEvent(m.targetEvent(row, now, row.State, store.TargetUnknown, reason)))
		row.State = store.TargetUnknown
		row.Since = now
		row.Reason = reason
		row.ConsecutiveOK = 0
		row.ConsecutiveFail = 0
		row.Transitions = ""
		row.FlappingUntil = 0
		if err := m.saveTarget(ctx, row); err != nil {
			return moved, err
		}
		moved++
	}
	if err := m.file(ctx, evs); err != nil {
		return moved, err
	}
	return moved, nil
}

// loadTarget reads one target row, returning nil when the mon-client has no
// such target: that is how a result for a target outside the current
// configuration is recognised (spec §7.1).
func (m *Machine) loadTarget(ctx context.Context, monClientID string, key TargetKey) (*store.Target, error) {
	var row store.Target
	err := m.st.DB().WithContext(ctx).
		Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ?",
			monClientID, key.InboundKind, key.InboundID, key.Path).
		Take(&row).Error
	switch {
	case err == nil:
		return &row, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	default:
		return nil, fmt.Errorf("state: read target %s of %s: %w", key, monClientID, err)
	}
}

// loadTargets reads every target of one mon-client.
func (m *Machine) loadTargets(ctx context.Context, monClientID string) ([]store.Target, error) {
	var rows []store.Target
	err := m.st.DB().WithContext(ctx).
		Where("mon_client_id = ?", monClientID).
		Order("inbound_kind, inbound_id, path").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("state: read targets of %s: %w", monClientID, err)
	}
	return rows, nil
}

// createTarget inserts a new target in UNKNOWN (spec §7.2: a new target starts
// unknown and waits for the first result of a live cycle).
func (m *Machine) createTarget(ctx context.Context, monClientID string, key TargetKey, now int64) (*store.Target, error) {
	row := &store.Target{
		MonClientID: monClientID,
		InboundKind: key.InboundKind,
		InboundID:   key.InboundID,
		Path:        key.Path,
		State:       store.TargetUnknown,
		Since:       now,
	}
	if err := m.st.DB().WithContext(ctx).Create(row).Error; err != nil {
		return nil, fmt.Errorf("state: create target %s of %s: %w", key, monClientID, err)
	}
	return row, nil
}

// saveTarget writes a target row back.
func (m *Machine) saveTarget(ctx context.Context, row *store.Target) error {
	if err := m.st.DB().WithContext(ctx).Save(row).Error; err != nil {
		return fmt.Errorf("state: save target %s of %s: %w", keyOf(row), row.MonClientID, err)
	}
	return nil
}
