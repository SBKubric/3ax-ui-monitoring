package store

import "encoding/json"

// EventPayload is the contract's event body (docs/spec/mon-protocol.md and
// the panel contract §4.6), the exact JSON EnqueueEvent stores in
// events_outbox.payload and POST /events later sends verbatim. InboundID is
// a pointer, not a plain int, because AWG's inbound id is 0 and
// `omitempty` on a bare int would drop that legitimate zero from the wire —
// a pointer round-trips "no inbound" (nil) and "inbound 0" (AWG)
// differently.
type EventPayload struct {
	ID   string `json:"id"`
	Ts   int64  `json:"ts"`
	Kind string `json:"kind"` // "target" | "mon_client" | "panel"

	MonClientID string `json:"monClientId,omitempty"`
	InboundKind string `json:"inboundKind,omitempty"`
	InboundID   *int   `json:"inboundId,omitempty"`
	Path        string `json:"path,omitempty"`

	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`

	// Notified is true once a Telegram message for this transition has gone
	// out (via the panel normally, or directly from mon-server in
	// PANEL_DOWN, spec §4.1) — the panel must not send a second one.
	Notified bool `json:"notified"`
}

// EnqueueEvent durably queues one event for the panel (spec §4 step 4) by
// marshalling it exactly as the wire form and inserting it into
// events_outbox with SentAt left nil. The outbox is the only path an event
// takes to the panel, including mon-server's own PANEL_DOWN/PANEL_UP
// transitions (spec §4.1) — there is no direct-send shortcut, so a crash
// between "decided" and "sent" never loses an event.
func (s *Store) EnqueueEvent(ev EventPayload) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	row := EventOutbox{
		Id:       ev.ID,
		Ts:       ev.Ts,
		Payload:  string(payload),
		Notified: ev.Notified,
	}
	return s.DB.Create(&row).Error
}
