package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// decode reads the stored payloads back into contract events. The payload is
// the wire shape the event was filed in, so this is a copy and not a
// re-derivation: a late event keeps its original timestamp.
//
// A payload that cannot be read is logged and left in the queue rather than
// marked delivered; the twenty-four hour cap of spec §4.1 eventually clears
// it, and the rest of the batch still goes out.
func decode(rows []store.EventOutbox, log *slog.Logger) ([]panel.Event, []string) {
	evs := make([]panel.Event, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ev, err := events.UnmarshalEvent(row.Payload)
		if err != nil {
			log.Error("unreadable event payload in the outbox, skipping it",
				"id", row.ID, "ts", row.TS, "error", err)
			continue
		}
		evs = append(evs, ev)
		ids = append(ids, row.ID)
	}
	return evs, ids
}

// stopping reports whether a failed request must end the drain instead of
// costing the batch. Those are the panel being unreachable — which the poll
// loop counts towards PANEL_DOWN (spec §4.1) — and mon-server's own context
// ending, which is the cycle running out or the process shutting down.
func stopping(ctx context.Context, err error) bool {
	if errors.Is(err, panel.ErrUnavailable) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return ctx.Err() != nil
}

// codeOf is the panel's stable error code for a refused batch, for the log
// line that records the drop.
func codeOf(err error) string {
	var apiErr *panel.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	if errors.Is(err, panel.ErrBatchTooLarge) {
		return panel.CodeBatchTooLarge
	}
	return ""
}

// statusOf is the HTTP status a refused batch came back with, 0 when the
// client refused it before sending.
func statusOf(err error) int {
	var apiErr *panel.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// firstIgnoredEvent names one ignored event for the log, so an operator can
// see which inbound the panel no longer has.
func firstIgnoredEvent(ignored []panel.IgnoredEvent) string {
	if len(ignored) == 0 {
		return ""
	}
	return fmt.Sprintf("%s: %s", ignored[0].ID, ignored[0].Error)
}

// firstIgnoredStat names one ignored aggregate for the log.
func firstIgnoredStat(ignored []panel.IgnoredStat) string {
	if len(ignored) == 0 {
		return ""
	}
	first := ignored[0]
	id := int64(0)
	if first.InboundID != nil {
		id = *first.InboundID
	}
	return fmt.Sprintf("%s %s:%d:%s bucket %d: %s",
		first.MonClientID, first.InboundKind, id, first.Path, first.BucketStart, first.Error)
}
