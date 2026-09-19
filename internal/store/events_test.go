package store

import (
	"encoding/json"
	"testing"
)

// TestEnqueueEvent_StoresExactPayload checks that EnqueueEvent's stored JSON
// round-trips every field, in particular that InboundID's zero value (AWG is
// always inboundId 0, mon-protocol.md §4.2) survives as a present 0 rather
// than being dropped by omitempty the way a bare int would be — this is the
// exact reason InboundID is a pointer.
func TestEnqueueEvent_StoresExactPayload(t *testing.T) {
	s := openTestStore(t)

	inboundID := 0
	ev := EventPayload{
		ID:          "018f0000-0000-7000-8000-000000000001",
		Ts:          1_700_000_000_000,
		Kind:        "target",
		MonClientID: "msk-1",
		InboundKind: InboundKindAwg,
		InboundID:   &inboundID,
		Path:        PathDirect,
		From:        TargetUp,
		To:          TargetDown,
		Reason:      "tcp_refused",
		Notified:    false,
	}

	if err := s.EnqueueEvent(ev); err != nil {
		t.Fatalf("EnqueueEvent: %v", err)
	}

	var row EventOutbox
	if err := s.DB.First(&row, "id = ?", ev.ID).Error; err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if row.Ts != ev.Ts {
		t.Fatalf("Ts = %d, want %d", row.Ts, ev.Ts)
	}
	if row.Notified != ev.Notified {
		t.Fatalf("Notified = %v, want %v", row.Notified, ev.Notified)
	}
	if row.SentAt != nil {
		t.Fatalf("SentAt = %v, want nil (not yet sent)", row.SentAt)
	}

	// The payload must contain a present "inboundId":0, not an omitted key —
	// this is the whole point of InboundID being a pointer.
	if !containsInboundIDZero(t, row.Payload) {
		t.Fatalf("payload missing present inboundId:0: %s", row.Payload)
	}

	var decoded EventPayload
	if err := json.Unmarshal([]byte(row.Payload), &decoded); err != nil {
		t.Fatalf("unmarshal stored payload: %v", err)
	}
	if decoded.InboundID == nil || *decoded.InboundID != 0 {
		t.Fatalf("decoded InboundID = %v, want pointer to 0", decoded.InboundID)
	}
	// InboundID is a pointer, so compare it by value and zero both sides
	// before the rest of the struct comparison.
	decoded.InboundID, ev.InboundID = nil, nil
	if decoded != ev {
		t.Fatalf("decoded payload (minus InboundID) = %+v, want %+v", decoded, ev)
	}
}

// containsInboundIDZero checks the raw JSON text for a present, non-omitted
// inboundId key, rather than trusting a round-trip through the same struct
// that wrote it (which could hide a bug where both sides agree on the wrong
// thing).
func containsInboundIDZero(t *testing.T, payload string) bool {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		t.Fatalf("unmarshal payload as map: %v", err)
	}
	v, ok := raw["inboundId"]
	return ok && string(v) == "0"
}

// TestEnqueueEvent_OmitsInboundIDWhenNil checks the other half of the
// contract: a panel-kind event, which has no inbound at all, must not gain a
// spurious inboundId key.
func TestEnqueueEvent_OmitsInboundIDWhenNil(t *testing.T) {
	s := openTestStore(t)

	ev := EventPayload{
		ID:       "018f0000-0000-7000-8000-000000000002",
		Ts:       1_700_000_000_000,
		Kind:     "panel",
		From:     "PANEL_UP",
		To:       "PANEL_DOWN",
		Reason:   "http_timeout",
		Notified: true,
	}
	if err := s.EnqueueEvent(ev); err != nil {
		t.Fatalf("EnqueueEvent: %v", err)
	}

	var row EventOutbox
	if err := s.DB.First(&row, "id = ?", ev.ID).Error; err != nil {
		t.Fatalf("read back row: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(row.Payload), &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := raw["inboundId"]; ok {
		t.Fatalf("payload has inboundId key, want it omitted: %s", row.Payload)
	}
}
