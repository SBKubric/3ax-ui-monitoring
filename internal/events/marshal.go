package events

import (
	"encoding/json"
	"fmt"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
)

// marshalEvent stores the event in the exact shape POST /events will send, so
// that draining the outbox is a copy rather than a re-derivation and a replay
// after PANEL_DOWN carries the original wording and timestamp.
func marshalEvent(ev panel.Event) (string, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("events: marshal: %w", err)
	}
	return string(b), nil
}

// UnmarshalEvent reads back what marshalEvent stored.
func UnmarshalEvent(payload string) (panel.Event, error) {
	var ev panel.Event
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return panel.Event{}, fmt.Errorf("events: unmarshal: %w", err)
	}
	return ev, nil
}
