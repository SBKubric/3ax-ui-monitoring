package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/SBKubric/3ax-ui-monitoring/internal/admin"
	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clientcfg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// The adapters below are the whole reason the packages underneath never import
// each other: each one declares the narrow interface it needs, and the wiring
// is the only place that knows both sides.

// registryPort adapts internal/registry to the port the admin UI declares.
type registryPort struct {
	reg *registry.Registry
	cfg *clientcfg.Builder
}

// PendingRequests implements admin.Registry.
func (p registryPort) PendingRequests(ctx context.Context) ([]admin.PendingRequest, error) {
	pending, err := p.reg.Pending(ctx)
	if err != nil {
		return nil, adminError(err)
	}
	out := make([]admin.PendingRequest, 0, len(pending))
	for _, r := range pending {
		hints := make([]admin.ReplacementHint, 0, len(r.Matches))
		for _, m := range r.Matches {
			// The port carries one reason per hint. A hostname match is the
			// stronger signal, so a request matching both is reported as the
			// hostname it is: an address can be reused by a different box.
			reason := admin.MatchIP
			if m.ByHostname {
				reason = admin.MatchHostname
			}
			hints = append(hints, admin.ReplacementHint{
				MonClientID: m.MonClientID,
				Name:        m.Name,
				Reason:      reason,
			})
		}
		out = append(out, admin.PendingRequest{
			RequestID:   r.RequestID,
			PairingCode: r.PairingCode,
			Hostname:    r.Hostname,
			Version:     r.Version,
			PublicIP:    r.PublicIP,
			RemoteIP:    r.RemoteIP,
			CreatedAt:   r.CreatedAt,
			ExpiresAt:   r.ExpiresAt,
			Attempt:     r.Attempt,
			Matches:     hints,
		})
	}
	return out, nil
}

// PendingCount implements admin.Registry.
func (p registryPort) PendingCount(ctx context.Context) (int, error) {
	n, err := p.reg.PendingCount(ctx)
	return n, adminError(err)
}

// Approve implements admin.Registry. The admin UI has already validated the
// shape; which of the two approval paths runs is the owner's explicit choice.
func (p registryPort) Approve(ctx context.Context, a admin.Approval) (admin.Client, error) {
	var (
		res registry.ApproveResult
		err error
	)
	if a.Replace {
		res, err = p.reg.ApproveAsReplacement(ctx, a.RequestID, a.MonClientID)
	} else {
		res, err = p.reg.Approve(ctx, a.RequestID, registry.ApproveInput{
			Name:   a.Name,
			Region: a.Region,
			Paths:  a.Paths,
		})
	}
	if err != nil {
		return admin.Client{}, adminError(err)
	}
	row, err := p.reg.Get(ctx, res.MonClientID)
	if err != nil {
		return admin.Client{}, adminError(err)
	}
	return p.client(ctx, row), nil
}

// Reject implements admin.Registry.
func (p registryPort) Reject(ctx context.Context, requestID string) error {
	return adminError(p.reg.Reject(ctx, requestID))
}

// Clients implements admin.Registry.
func (p registryPort) Clients(ctx context.Context) ([]admin.Client, error) {
	rows, err := p.reg.List(ctx)
	if err != nil {
		return nil, adminError(err)
	}
	out := make([]admin.Client, 0, len(rows))
	for _, row := range rows {
		out = append(out, p.client(ctx, row))
	}
	return out, nil
}

// UpdateClient implements admin.Registry.
func (p registryPort) UpdateClient(ctx context.Context, id string, e admin.ClientEdit) error {
	return adminError(p.reg.Update(ctx, id, e.Name, e.Region, e.Paths))
}

// SetClientEnabled implements admin.Registry.
func (p registryPort) SetClientEnabled(ctx context.Context, id string, enabled bool) error {
	if enabled {
		return adminError(p.reg.Enable(ctx, id))
	}
	return adminError(p.reg.Disable(ctx, id))
}

// RevokeClient implements admin.Registry.
func (p registryPort) RevokeClient(ctx context.Context, id string) error {
	return adminError(p.reg.Revoke(ctx, id))
}

// DeleteClient implements admin.Registry.
func (p registryPort) DeleteClient(ctx context.Context, id string) error {
	return adminError(p.reg.Delete(ctx, id))
}

// client converts a registry row, filling in the revision mon-server built for
// that mon-client so the table can show it next to the one the box reports
// running (§9.3).
func (p registryPort) client(ctx context.Context, row registry.Client) admin.Client {
	c := admin.Client{
		ID:              row.ID,
		Name:            row.Name,
		Region:          row.Region,
		Paths:           row.Paths,
		Enabled:         row.Enabled,
		State:           row.State,
		LastHeartbeat:   row.LastHeartbeat,
		ApprovedAt:      row.ApprovedAt,
		Version:         row.Version,
		XrayVersion:     row.XrayVersion,
		AppliedRevision: row.AppliedRevision,
		ConfigError:     row.ConfigError,
		ConfigErrorAt:   row.ConfigErrorAt,
		RemoteIP:        row.RemoteIP,
		TokenRevoked:    !row.HasToken,
	}
	if p.cfg != nil {
		if _, revision, err := p.cfg.Document(ctx, row.ID); err == nil {
			c.ConfigRevision = revision
		}
	}
	return c
}

// adminError translates a registry failure into the vocabulary the admin UI
// turns into a status code. Without it every one of them would surface as an
// internal error, so a mon-client that has just been deleted in another tab
// would answer 500 instead of "not found", and a rejected name would look like
// a broken server rather than a correction the owner can make.
func adminError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, registry.ErrRequestNotFound), errors.Is(err, registry.ErrMonClientNotFound):
		return fmt.Errorf("%w: %s", admin.ErrNotFound, err)
	case errors.Is(err, registry.ErrRequestExpired), errors.Is(err, registry.ErrRequestNotPending),
		errors.Is(err, registry.ErrNoFreeID):
		return fmt.Errorf("%w: %s", admin.ErrConflict, err)
	case errors.Is(err, registry.ErrEmptyName), errors.Is(err, registry.ErrInvalidPaths),
		errors.Is(err, registry.ErrInvalidRequest):
		return fmt.Errorf("%w: %s", admin.ErrInvalid, err)
	default:
		return err
	}
}

// panelCheckPort runs the Check button: one GET /state with the values as
// typed, through a throwaway client, saving nothing.
type panelCheckPort struct {
	httpClient *http.Client
	clock      clock.Clock
	log        *slog.Logger
}

// CheckPanel implements admin.PanelChecker.
func (p panelCheckPort) CheckPanel(ctx context.Context, panelURL, monToken string) (admin.PanelCheck, error) {
	client, err := panel.New(panel.Options{
		BaseURL:    panelURL,
		Token:      monToken,
		HTTPClient: p.httpClient,
		Clock:      p.clock,
		Log:        p.log,
	})
	if err != nil {
		return admin.PanelCheck{}, err
	}
	state, err := client.State(ctx)
	if err != nil {
		return admin.PanelCheck{}, err
	}
	return admin.PanelCheck{
		Revision:        state.Revision,
		Inbounds:        len(state.Inbounds),
		OverrideEnabled: state.Override.Enabled,
		OverrideHost:    state.Override.Host,
		PanelVersion:    state.PanelVersion,
	}, nil
}

// telegramPort runs the Send test button with the values as typed.
type telegramPort struct {
	httpClient *http.Client
	log        *slog.Logger
}

// SendTestMessage implements admin.TelegramTester.
func (p telegramPort) SendTestMessage(ctx context.Context, tgToken, tgChatID string) error {
	return tg.New(tgToken, tgChatID, p.httpClient, p.log).SendTest(ctx)
}

// rebuildPort is the rebuild a settings change triggers. It rebuilds each
// mon-client from the targets it already has, which is right for a probe
// parameter change. A realHost change also needs the panel to re-render the
// direct links, and the next poll does that: the rebuild here moves the
// revision immediately, the poll corrects the links within the minute.
type rebuildPort struct {
	cfg *clientcfg.Builder
	log *slog.Logger
}

// RebuildAll implements admin.ConfigRebuilder.
func (p rebuildPort) RebuildAll(ctx context.Context) error {
	results, err := p.cfg.RebuildAll(ctx, clientcfg.Input{KeepTargets: true})
	if err != nil {
		return err
	}
	changed := 0
	for _, r := range results {
		if r.Changed {
			changed++
		}
	}
	p.log.Info("rebuilt mon-client configs after a settings change",
		"mon_clients", len(results), "revisions_changed", changed)
	return nil
}

// telegramAlert is the alert hook the panel client and the state machine use.
// It reads the bot token and chat id from settings on every message rather
// than capturing them, so changing them in the admin UI takes effect at once
// instead of at the next restart.
func telegramAlert(st *store.Store, httpClient *http.Client, log *slog.Logger) alert.Func {
	notConfigured := alert.Logged(log)
	return func(ctx context.Context, text string) {
		settings, err := st.Settings()
		if err != nil {
			log.Error("cannot read the telegram settings for an alert", "err", err, "text", text)
			return
		}
		sender := tg.New(settings.TGToken, settings.TGChatID, httpClient, log)
		if !sender.Configured() {
			notConfigured(ctx, text)
			return
		}
		sender.Alert()(ctx, text)
	}
}

// probeConfigs turns the poll's per-path material into the builder's input.
func probeConfigs(cfgs map[string]panel.ProbeConfigs) clientcfg.Input {
	in := clientcfg.Input{}
	if c, ok := cfgs[panel.PathProxy]; ok {
		in.Proxy = &c
	}
	if c, ok := cfgs[panel.PathDirect]; ok {
		in.Direct = &c
	}
	return in
}

// errNoPanelSettings is reported by the poll loop while the panel address or
// the monitoring token has not been filled in yet. It is a normal state on a
// fresh box, not a failure of the panel, so it never counts towards declaring
// the panel down.
var errNoPanelSettings = errors.New("app: the panel url or the monitoring token is not configured yet")

// panelClientFor builds the contract client from the current settings.
func panelClientFor(settings store.Settings, httpClient *http.Client, clk clock.Clock, log *slog.Logger) (*panel.Client, error) {
	if settings.PanelURL == "" || settings.MonToken == "" {
		return nil, errNoPanelSettings
	}
	client, err := panel.New(panel.Options{
		BaseURL:    settings.PanelURL,
		Token:      settings.MonToken,
		HTTPClient: httpClient,
		Clock:      clk,
		Log:        log,
	})
	if err != nil {
		return nil, fmt.Errorf("app: panel client: %w", err)
	}
	return client, nil
}
