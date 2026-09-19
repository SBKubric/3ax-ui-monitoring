package tg

import (
	"context"
	"log/slog"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// CredentialsSource is the seam NewFromSettings depends on instead of a
// concrete *store.Store, so a test can supply fixed or changing
// tgToken/tgChatId pairs without a real database. *store.Store satisfies it
// via LoadSettings.
type CredentialsSource interface {
	LoadSettings() (*store.Settings, error)
}

// settingsNotifier is the Notifier the rest of mon-server actually uses: it
// defers to src for tgToken/tgChatId on every Send (spec §9.4 — every knob
// comes from Settings, read fresh, never cached, because an admin can save
// new credentials at runtime and the very next message must use them).
type settingsNotifier struct {
	src CredentialsSource
	h   *HTTP

	mu             sync.Mutex
	warnedNotSetUp bool // true once "telegram not configured" has been logged for the current spell
}

// NewFromSettings builds the Notifier that internal/panel and internal/state
// send through. When Settings has no tgToken or no tgChatId yet, Send is a
// no-op that logs "telegram not configured" once per spell of missing
// credentials (logging again only after a Send has gone out with
// credentials in between) rather than once per message, since an operator
// who has not filled in the Telegram tab yet does not need a log line every
// poll cycle.
func NewFromSettings(src CredentialsSource, h *HTTP) Notifier {
	return &settingsNotifier{src: src, h: h}
}

// Send loads the current credentials and either delivers text through h or,
// if nothing is configured, logs once per spell and reports success — a
// missing bot token must never look like a delivery failure to the caller
// (see internal/tg/tg.go's Nop for why: mon-server has to keep running with
// no bot configured at all).
func (n *settingsNotifier) Send(ctx context.Context, text string) error {
	set, err := n.src.LoadSettings()
	if err != nil {
		return err
	}

	if set.TgToken == "" || set.TgChatID == "" {
		n.mu.Lock()
		already := n.warnedNotSetUp
		n.warnedNotSetUp = true
		n.mu.Unlock()
		if !already {
			slog.Warn("telegram not configured")
		}
		return nil
	}

	n.mu.Lock()
	n.warnedNotSetUp = false
	n.mu.Unlock()

	return n.h.SendTo(ctx, set.TgToken, set.TgChatID, text)
}
