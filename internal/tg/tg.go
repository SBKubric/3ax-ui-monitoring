// Package tg is the seam every mon-server package that sends Telegram
// messages depends on (spec §8), instead of on a concrete Bot API client.
// This step only defines the interface and two test/placeholder
// implementations; step 9 adds the real client and message formatters. Until
// then, every caller takes a Notifier and every test passes a *Recorder.
package tg

import (
	"context"
	"sync"
)

// Notifier sends a single already-formatted message to the configured
// Telegram chat. Callers format the text (spec §8 gives the exact wordings);
// Notifier only knows how to deliver it.
type Notifier interface {
	Send(ctx context.Context, text string) error
}

// Nop is a Notifier that discards every message. It is the default before an
// operator has set tgToken/tgChatId in settings (§9.4): mon-server must run
// and log transitions even with no bot configured, not fail to start.
type Nop struct{}

// Send always succeeds and sends nothing.
func (Nop) Send(context.Context, string) error { return nil }

// Recorder is a Notifier for tests: it keeps every message it was asked to
// send, in order, so a test can assert on exactly what would have gone to
// Telegram without a network call or a real bot token.
type Recorder struct {
	mu   sync.Mutex
	Sent []string
}

// Send appends text to Sent and always succeeds.
func (r *Recorder) Send(_ context.Context, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Sent = append(r.Sent, text)
	return nil
}
