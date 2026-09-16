// Package alert carries the Telegram hook that mon-server components call when
// they need to notify the owner themselves (spec mon-server.md §8). Keeping the
// hook a bare function type lets the panel client, the state machine and the
// registry alert without importing the Telegram client.
package alert

import (
	"context"
	"log/slog"
)

// Func sends one plain-text message to the owner. Implementations never block
// their caller's cycle on a Telegram failure: they log and return.
type Func func(ctx context.Context, text string)

// Discard drops every message. It is the zero value used before Telegram is
// configured and in tests that do not assert on alerts.
func Discard(context.Context, string) {}

// Logged returns a Func that records messages through log instead of sending
// them, used when no Telegram bot token is configured.
func Logged(log *slog.Logger) Func {
	return func(_ context.Context, text string) {
		log.Info("alert not sent, telegram is not configured", "text", text)
	}
}
