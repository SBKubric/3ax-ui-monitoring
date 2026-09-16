// Package events files state transitions into the outbox the panel poll drains.
//
// It exists so that every producer of an event — the registry disabling a
// mon-client, the state machine moving a target, the panel client declaring
// the panel down — files it the same way, and so that the rule of
// mon-server.md §4.1 lives in exactly one place: while the panel is
// unreachable, mon-server announces transitions to Telegram itself, marks them
// notified so the panel does not announce them again when they are finally
// delivered, and keeps them queued.
package events

import (
	"context"
	"fmt"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Outbox writes events into events_outbox, applying the PANEL_DOWN policy.
type Outbox struct {
	st      *store.Store
	alertFn alert.Func
}

// New returns an Outbox. alertFn may be nil, meaning alerts are dropped.
func New(st *store.Store, alertFn alert.Func) *Outbox {
	if alertFn == nil {
		alertFn = alert.Discard
	}
	return &Outbox{st: st, alertFn: alertFn}
}

// TargetKey is the "kind:inboundId:path" form a tunnel probe uses and the
// Telegram text names a target by.
func TargetKey(inboundKind string, inboundID int64, path string) string {
	return fmt.Sprintf("%s:%d:%s", inboundKind, inboundID, path)
}

// Target builds a target transition event. ts is the time mon-server decided
// the transition, which is its own receive time, not the mon-client's clock.
func Target(ts int64, monClientID, inboundKind string, inboundID int64, path, from, to, reason string) panel.Event {
	id := inboundID
	return panel.Event{
		TS:          ts,
		Kind:        panel.EventKindTarget,
		MonClientID: monClientID,
		InboundKind: inboundKind,
		InboundID:   &id,
		Path:        path,
		From:        from,
		To:          to,
		Reason:      reason,
	}
}

// MonClient builds a mon-client transition event.
func MonClient(ts int64, monClientID, from, to, reason string) panel.Event {
	return panel.Event{
		TS:          ts,
		Kind:        panel.EventKindMonClient,
		MonClientID: monClientID,
		From:        from,
		To:          to,
		Reason:      reason,
	}
}

// Panel builds a panel transition event. Those are always notified: the panel
// client has already told Telegram, and the panel only files them.
func Panel(ts int64, from, to, reason string) panel.Event {
	return panel.Event{
		TS:       ts,
		Kind:     panel.EventKindPanel,
		From:     from,
		To:       to,
		Reason:   reason,
		Notified: true,
	}
}

// Enqueue files one event. When the panel is down and the event is a target or
// mon-client transition, it is announced to Telegram here, marked notified, and
// still queued for delivery once the panel is back.
func (o *Outbox) Enqueue(ctx context.Context, ev panel.Event) error {
	return o.EnqueueAll(ctx, []panel.Event{ev})
}

// EnqueueAll files a batch in one transaction, so a caller that moves several
// targets at once — a mon-client going offline, an inbound being disabled —
// cannot leave half of them unrecorded.
func (o *Outbox) EnqueueAll(ctx context.Context, evs []panel.Event) error {
	if len(evs) == 0 {
		return nil
	}
	panelDown, err := o.panelIsDown()
	if err != nil {
		return err
	}

	rows := make([]store.EventOutbox, 0, len(evs))
	alerts := make([]string, 0, len(evs))
	for _, ev := range evs {
		if ev.ID == "" {
			id, err := store.NewEventID()
			if err != nil {
				return fmt.Errorf("events: new id: %w", err)
			}
			ev.ID = id
		}
		if ev.TS == 0 {
			ev.TS = o.st.NowMS()
		}
		if panelDown && ev.Kind != panel.EventKindPanel {
			text, err := o.announce(ev)
			if err != nil {
				return err
			}
			if text != "" {
				ev.Notified = true
				alerts = append(alerts, text)
			}
		}
		ev = ev.Normalized()

		payload, err := marshalEvent(ev)
		if err != nil {
			return err
		}
		rows = append(rows, store.EventOutbox{
			ID:       ev.ID,
			TS:       ev.TS,
			Payload:  payload,
			Notified: ev.Notified,
		})
	}

	if err := o.st.DB().WithContext(ctx).Create(&rows).Error; err != nil {
		return fmt.Errorf("events: enqueue: %w", err)
	}
	// Alert only after the events are durable: a Telegram message about a
	// transition mon-server then forgot would be worse than a late one.
	for _, text := range alerts {
		o.alertFn(ctx, text)
	}
	return nil
}

// announce phrases the Telegram message for a transition mon-server has to
// send itself. It returns an empty string for an event kind that is not
// announced.
func (o *Outbox) announce(ev panel.Event) (string, error) {
	switch ev.Kind {
	case panel.EventKindTarget:
		var inboundID int64
		if ev.InboundID != nil {
			inboundID = *ev.InboundID
		}
		key := TargetKey(ev.InboundKind, inboundID, ev.Path)
		return alert.MsgTargetTransition(ev.MonClientID, key, ev.From, ev.To, ev.Reason), nil
	case panel.EventKindMonClient:
		name, region, err := o.monClientLabel(ev.MonClientID)
		if err != nil {
			return "", err
		}
		return alert.MsgMonClientTransition(name, region, ev.To), nil
	default:
		return "", nil
	}
}

// monClientLabel reads the name and region the alert names a mon-client by,
// falling back to its id when the row is gone.
func (o *Outbox) monClientLabel(id string) (name, region string, err error) {
	var mc store.MonClient
	res := o.st.DB().Where("id = ?", id).Take(&mc)
	if res.Error != nil {
		return id, "", nil //nolint:nilerr // a deleted mon-client still gets an alert, named by id
	}
	name = mc.Name
	if name == "" {
		name = mc.ID
	}
	return name, mc.Region, nil
}

func (o *Outbox) panelIsDown() (bool, error) {
	ps, err := o.st.PanelState()
	if err != nil {
		return false, fmt.Errorf("events: panel state: %w", err)
	}
	return ps.Status == store.PanelStatusDown, nil
}
