package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Client is one registry row as the admin UI reads it (spec §9.3): the stored
// row with its paths decoded and its token reduced to whether there still is
// one. The hash never leaves this package.
type Client struct {
	ID               string
	Name             string
	Region           string
	Paths            []string
	Enabled          bool
	State            string
	LastHeartbeat    int64
	Version          string
	XrayVersion      string
	AppliedRevision  string
	ConfigError      string
	ConfigErrorAt    int64
	RemoteIP         string
	ApprovedAt       int64
	MissedHeartbeats int
	// HasToken is false once the token has been revoked, which is what the
	// admin UI's Revoke leaves behind.
	HasToken bool
}

// List returns every mon-client, ordered by id.
func (r *Registry) List(ctx context.Context) ([]Client, error) {
	var rows []store.MonClient
	if err := r.st.DB().WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("registry: list mon-clients: %w", err)
	}
	out := make([]Client, 0, len(rows))
	for _, row := range rows {
		client, err := toClient(row)
		if err != nil {
			return nil, err
		}
		out = append(out, client)
	}
	return out, nil
}

// Get returns one mon-client, or ErrMonClientNotFound.
func (r *Registry) Get(ctx context.Context, id string) (Client, error) {
	row, err := r.row(ctx, id)
	if err != nil {
		return Client{}, err
	}
	return toClient(row)
}

// Update changes what the administrator may change about a mon-client
// (spec §9.3): its name, its region and its probe paths. The id is derived
// from the name once, at approval, and never moves afterwards — the panel, the
// targets and the statistics are all keyed by it.
func (r *Registry) Update(ctx context.Context, id, name, region string, paths []string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrEmptyName
	}
	normalised, err := normalisePaths(paths)
	if err != nil {
		return err
	}
	encoded, err := store.EncodePaths(normalised)
	if err != nil {
		return err
	}
	if _, err := r.row(ctx, id); err != nil {
		return err
	}
	updates := map[string]any{"name": name, "region": strings.TrimSpace(region), "paths": encoded}
	if err := r.st.DB().WithContext(ctx).Model(&store.MonClient{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("registry: update mon-client %s: %w", id, err)
	}
	r.log.Info("mon-client updated", "monClientId", id, "paths", normalised)
	return nil
}

// Revoke invalidates the client token (spec §6). The row stays: the box will
// get 401 token_revoked, wipe its state file and file a fresh registration
// request, which the administrator can approve as this mon-client's
// replacement to give it its id back.
func (r *Registry) Revoke(ctx context.Context, id string) error {
	if _, err := r.row(ctx, id); err != nil {
		return err
	}
	updates := map[string]any{"token_hash": "", "state": store.ClientStateOffline}
	if err := r.st.DB().WithContext(ctx).Model(&store.MonClient{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("registry: revoke mon-client %s: %w", id, err)
	}
	r.log.Info("client token revoked", "monClientId", id)
	return nil
}

// Disable switches a mon-client off (spec §6). Its targets stop meaning
// anything, so they go to UNKNOWN with reason mon_client_disabled and the
// panel is told about each of them; the mon-client itself stays in the
// registry and in the snapshot the panel is sent.
func (r *Registry) Disable(ctx context.Context, id string) error {
	if _, err := r.row(ctx, id); err != nil {
		return err
	}
	now := r.nowMS()
	db := r.st.DB().WithContext(ctx)

	// The targets are read and moved in one transaction, so the states the
	// events report are the ones that were actually replaced.
	var targets []store.Target
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.MonClient{}).Where("id = ?", id).Update("enabled", false).Error; err != nil {
			return fmt.Errorf("registry: disable mon-client %s: %w", id, err)
		}
		err := tx.Where("mon_client_id = ? AND state <> ?", id, store.TargetUnknown).
			Order("id ASC").Find(&targets).Error
		if err != nil {
			return fmt.Errorf("registry: list targets of %s: %w", id, err)
		}
		if len(targets) == 0 {
			return nil
		}
		updates := map[string]any{
			"state":            store.TargetUnknown,
			"since":            now,
			"reason":           panel.ReasonMonClientDisabled,
			"consecutive_fail": 0,
			"consecutive_ok":   0,
		}
		err = tx.Model(&store.Target{}).
			Where("mon_client_id = ? AND state <> ?", id, store.TargetUnknown).
			Updates(updates).Error
		if err != nil {
			return fmt.Errorf("registry: unknown targets of %s: %w", id, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// The outbox has its own transaction, so the events are filed once the
	// states are durable: an event about a transition that did not happen
	// would be worse than an unannounced one, which the next snapshot repairs.
	evs := make([]panel.Event, 0, len(targets))
	for _, t := range targets {
		evs = append(evs, events.Target(now, id, t.InboundKind, t.InboundID, t.Path,
			t.State, store.TargetUnknown, panel.ReasonMonClientDisabled))
	}
	if err := r.ob.EnqueueAll(ctx, evs); err != nil {
		return fmt.Errorf("registry: file target events of %s: %w", id, err)
	}
	r.log.Info("mon-client disabled", "monClientId", id, "targets", len(targets))
	return nil
}

// Enable switches a mon-client back on (spec §6). Its targets stay UNKNOWN
// until probe results arrive: mon-server does not guess what the box will
// find.
func (r *Registry) Enable(ctx context.Context, id string) error {
	if _, err := r.row(ctx, id); err != nil {
		return err
	}
	if err := r.st.DB().WithContext(ctx).Model(&store.MonClient{}).Where("id = ?", id).Update("enabled", true).Error; err != nil {
		return fmt.Errorf("registry: enable mon-client %s: %w", id, err)
	}
	r.log.Info("mon-client enabled", "monClientId", id)
	return nil
}

// Delete removes a mon-client together with everything keyed by it that only
// describes it: its targets and its built configuration (spec §6). The panel
// drops its rows once the next registry snapshot arrives without this id.
// There are no foreign keys between these tables, so the cascade is explicit.
func (r *Registry) Delete(ctx context.Context, id string) error {
	err := r.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ?", id).Delete(&store.MonClient{})
		if res.Error != nil {
			return fmt.Errorf("registry: delete mon-client %s: %w", id, res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrMonClientNotFound
		}
		if err := tx.Where("mon_client_id = ?", id).Delete(&store.Target{}).Error; err != nil {
			return fmt.Errorf("registry: delete targets of %s: %w", id, err)
		}
		if err := tx.Where("mon_client_id = ?", id).Delete(&store.ClientConfig{}).Error; err != nil {
			return fmt.Errorf("registry: delete config of %s: %w", id, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.log.Info("mon-client deleted", "monClientId", id)
	return nil
}

// Snapshot is the registry as POST /probe/ensure sends it (spec §4 step 2):
// every mon-client, the disabled and the never-seen included, because the
// panel shows them as they are rather than filtering them out.
func (r *Registry) Snapshot(ctx context.Context) ([]panel.MonClientSnapshot, error) {
	var rows []store.MonClient
	if err := r.st.DB().WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("registry: read registry snapshot: %w", err)
	}
	out := make([]panel.MonClientSnapshot, 0, len(rows))
	for _, row := range rows {
		out = append(out, panel.MonClientSnapshot{
			ID:            row.ID,
			Name:          row.Name,
			Region:        row.Region,
			State:         row.State,
			LastHeartbeat: row.LastHeartbeat,
		})
	}
	return out, nil
}

// row reads one mon-client, mapping a missing row to ErrMonClientNotFound.
func (r *Registry) row(ctx context.Context, id string) (store.MonClient, error) {
	var mc store.MonClient
	err := r.st.DB().WithContext(ctx).Where("id = ?", id).Take(&mc).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.MonClient{}, ErrMonClientNotFound
	case err != nil:
		return store.MonClient{}, fmt.Errorf("registry: read mon-client %s: %w", id, err)
	}
	return mc, nil
}

// toClient projects a stored row into the admin UI's view of it.
func toClient(row store.MonClient) (Client, error) {
	paths, err := store.DecodePaths(row.Paths)
	if err != nil {
		return Client{}, err
	}
	return Client{
		ID:               row.ID,
		Name:             row.Name,
		Region:           row.Region,
		Paths:            paths,
		Enabled:          row.Enabled,
		State:            row.State,
		LastHeartbeat:    row.LastHeartbeat,
		Version:          row.Version,
		XrayVersion:      row.XrayVersion,
		AppliedRevision:  row.AppliedRevision,
		ConfigError:      row.ConfigError,
		ConfigErrorAt:    row.ConfigErrorAt,
		RemoteIP:         row.RemoteIP,
		ApprovedAt:       row.ApprovedAt,
		MissedHeartbeats: row.MissedHeartbeats,
		HasToken:         row.TokenHash != "",
	}, nil
}
