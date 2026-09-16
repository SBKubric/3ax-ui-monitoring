package clientcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Errors a caller branches on.
var (
	// ErrNoConfig reports that no configuration has been assembled for a
	// mon-client yet. It is the normal state of a freshly approved mon-client
	// until the next panel poll, not a failure.
	ErrNoConfig = errors.New("clientcfg: no configuration built for this mon-client")
	// ErrUnknownMonClient reports a mon-client id that is not in the registry.
	ErrUnknownMonClient = errors.New("clientcfg: unknown mon-client")
	// ErrNoProbeEndpoint reports that no public address is configured, so the
	// probe url — and with it the whole document — cannot be rendered.
	ErrNoProbeEndpoint = errors.New("clientcfg: no public address for the probe url")
	// ErrRevisionMismatch reports probe configs fetched at different panel
	// revisions. Mixing them would describe a panel state that never existed
	// (spec §4 step 3 drops the stale answer instead).
	ErrRevisionMismatch = errors.New("clientcfg: probe configs come from different panel revisions")
)

// Builder assembles per-mon-client configuration documents from the panel
// material of one poll and keeps them in client_configs.
//
// One Builder serves every mon-client: what differs between them is only the
// set of paths chosen at approval time.
type Builder struct {
	st       *store.Store
	clk      clock.Clock
	log      *slog.Logger
	listen   string
	publicIP string
}

// Option customises New.
type Option func(*Builder)

// WithClock replaces the store's clock, which stamps client_configs.built_at.
func WithClock(c clock.Clock) Option {
	return func(b *Builder) {
		if c != nil {
			b.clk = c
		}
	}
}

// WithLogger replaces the store's logger.
func WithLogger(l *slog.Logger) Option {
	return func(b *Builder) {
		if l != nil {
			b.log = l
		}
	}
}

// WithProbeEndpoint sets the two bootstrap values the probe url is rendered
// from: the listen address of mon-server's single HTTPS listener and the
// public IP mon-clients reach it at.
//
// They arrive as plain strings rather than as the bootstrap configuration
// itself so that assembling a document stays a pure function of its inputs,
// and so that this package does not depend on how mon-server is configured.
func WithProbeEndpoint(listen, publicIP string) Option {
	return func(b *Builder) {
		b.listen = listen
		b.publicIP = publicIP
	}
}

// New returns a Builder over st. Without WithProbeEndpoint the builder has no
// public address and every build fails with ErrNoProbeEndpoint.
func New(st *store.Store, opts ...Option) *Builder {
	b := &Builder{st: st}
	if st != nil {
		b.clk = st.Clock()
		b.log = st.Log()
	}
	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}
	if b.clk == nil {
		b.clk = clock.System{}
	}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	return b
}

// ProbeURL is the tunnel probe endpoint this builder writes into every
// document, empty when no public address was configured.
func (b *Builder) ProbeURL() string { return ProbeURL(b.listen, b.publicIP) }

// Input is the panel material one rebuild works from: the answers of the last
// GET /probe/configs per path, and the inbound list of the GET /state they
// belong to.
type Input struct {
	// PanelRevision is the revision the caller polled at. Left empty, the
	// revision carried by the answers themselves is used.
	PanelRevision string
	// Proxy is GET /probe/configs, the path "proxy" set. It is nil when the
	// panel's host override is disabled — the panel answers 409
	// override_disabled then — and no mon-client gets proxy targets.
	Proxy *panel.ProbeConfigs
	// Direct is GET /probe/configs?host=<realHost>, the path "direct" set.
	Direct *panel.ProbeConfigs
	// Inbounds is the inbound list of GET /state. Only Kind, InboundID and
	// Protocol are read: an inbound's remark, port or enabled flag must not
	// move a config revision, and a disabled inbound is already absent from
	// the items above, which is how mon-server sees PAUSED (protocol §4.2).
	//
	// Left empty, the protocols are read from panel_inbounds, the mirror the
	// poll writes from the same GET /state one step earlier (spec §4 step 1),
	// so a caller holding only the probe configs does not have to carry the
	// inbound list along.
	Inbounds []panel.Inbound
	// KeepTargets rebuilds each mon-client from the targets it already has
	// instead of from Proxy and Direct.
	//
	// It is for the rebuild that has no fresh panel material: saving a probe
	// parameter changes only mon-server's own half of the document (§9.4
	// Save), and refetching the probe set to change a timeout would be a
	// round trip that can fail for no reason. Paths still apply, so narrowing
	// a mon-client to the proxy route drops its direct targets; a mon-client
	// with no document yet has no targets to keep and is left alone.
	KeepTargets bool
}

// Result is what one mon-client's rebuild produced.
type Result struct {
	MonClientID string
	// Revision is the config revision now stored for this mon-client.
	Revision string
	// Previous is the revision it replaced, empty when there was none.
	Previous string
	// Changed says whether the mon-client has to fetch GET /v1/config again:
	// the next heartbeat answer carries Revision and it differs from what the
	// mon-client applied.
	Changed bool
	// Document is the stored document, byte for byte what GET /v1/config
	// serves.
	Document json.RawMessage
}

// BuildFor rebuilds one mon-client's configuration from in, writes it to
// client_configs and reports the revision and whether it changed.
func (b *Builder) BuildFor(ctx context.Context, monClientID string, in Input) (Result, error) {
	mc, err := b.monClient(ctx, monClientID)
	if err != nil {
		return Result{}, err
	}
	material, err := b.prepare(ctx, in)
	if err != nil {
		return Result{}, err
	}
	return b.buildOne(ctx, mc, material)
}

// RebuildAll rebuilds every mon-client in the registry, which is what a panel
// revision change, a probe parameter change or a realHost change calls for
// (spec §4 step 3, §9.4 Save).
//
// A mon-client whose own row cannot be turned into a document does not stop
// the others: its error is logged, joined into the returned error and left out
// of the map, so the caller sees both what was rebuilt and what was not.
func (b *Builder) RebuildAll(ctx context.Context, in Input) (map[string]Result, error) {
	material, err := b.prepare(ctx, in)
	if err != nil {
		return nil, err
	}
	var rows []store.MonClient
	if err := b.st.DB().WithContext(ctx).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("clientcfg: list mon-clients: %w", err)
	}
	results := make(map[string]Result, len(rows))
	var failed error
	for _, mc := range rows {
		res, err := b.buildOne(ctx, mc, material)
		if errors.Is(err, ErrNoConfig) {
			// KeepTargets over a mon-client that has never been built: there
			// is nothing to keep, and inventing an empty document would tell
			// it to probe nothing.
			continue
		}
		if err != nil {
			b.log.Error("rebuild mon-client config", "monClientId", mc.ID, "error", err)
			failed = errors.Join(failed, err)
			continue
		}
		results[mc.ID] = res
	}
	return results, failed
}

// Document returns the stored configuration document and its revision, for
// GET /v1/config. It reports ErrNoConfig when nothing has been built yet.
func (b *Builder) Document(ctx context.Context, monClientID string) (json.RawMessage, string, error) {
	var row store.ClientConfig
	err := b.st.DB().WithContext(ctx).Where("mon_client_id = ?", monClientID).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, "", fmt.Errorf("%w: %s", ErrNoConfig, monClientID)
	case err != nil:
		return nil, "", fmt.Errorf("clientcfg: read config of %s: %w", monClientID, err)
	}
	return json.RawMessage(row.Document), row.Revision, nil
}

// Targets is the set of targets in a mon-client's current configuration: what
// the state machine holds state for and what a tunnel probe may name. It reads
// the stored document, so it answers exactly what the mon-client was told, and
// reports ErrNoConfig when the mon-client has not been told anything yet.
func (b *Builder) Targets(ctx context.Context, monClientID string) ([]Target, error) {
	raw, _, err := b.Document(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Targets []Target `json:"targets"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("clientcfg: parse stored config of %s: %w", monClientID, err)
	}
	return doc.Targets, nil
}

// material is everything a rebuild shares between mon-clients: computed once,
// so that RebuildAll reads the settings and indexes the panel answers once for
// the whole registry.
type material struct {
	probe    Probe
	probeURL string
	// keepTargets carries Input.KeepTargets through to the per-mon-client
	// step, which then reads the targets from the stored document.
	keepTargets bool
	// items holds the panel's probe set per path; a path the panel did not
	// answer for is simply absent.
	items map[string][]panel.ConfigItem
	// protocols maps an inbound to the protocol GET /state reported for it.
	protocols map[inboundKey]string
}

// inboundKey identifies an inbound across the two paths.
type inboundKey struct {
	kind string
	id   int64
}

// prepare validates in and turns it into the material every mon-client of this
// rebuild is assembled from.
func (b *Builder) prepare(ctx context.Context, in Input) (material, error) {
	probeURL := b.ProbeURL()
	if probeURL == "" {
		return material{}, ErrNoProbeEndpoint
	}
	if _, err := in.panelRevision(); err != nil {
		return material{}, err
	}
	settings, err := b.st.Settings()
	if err != nil {
		return material{}, fmt.Errorf("clientcfg: read settings: %w", err)
	}
	m := material{
		probe:       probeFromSettings(settings),
		probeURL:    probeURL,
		keepTargets: in.KeepTargets,
		items:       make(map[string][]panel.ConfigItem, 2),
	}
	if in.KeepTargets {
		return m, nil
	}
	if in.Proxy != nil {
		m.items[panel.PathProxy] = in.Proxy.Items
	}
	if in.Direct != nil {
		m.items[panel.PathDirect] = in.Direct.Items
	}
	if m.protocols, err = b.protocolIndex(ctx, in.Inbounds); err != nil {
		return material{}, err
	}
	return m, nil
}

// protocolIndex maps every inbound to the protocol GET /state reported for it,
// from the caller's own copy of the list or, when it has none, from the
// panel_inbounds mirror of the same answer.
func (b *Builder) protocolIndex(ctx context.Context, inbounds []panel.Inbound) (map[inboundKey]string, error) {
	if len(inbounds) > 0 {
		index := make(map[inboundKey]string, len(inbounds))
		for _, inbound := range inbounds {
			index[inboundKey{kind: inbound.Kind, id: inbound.InboundID}] = inbound.Protocol
		}
		return index, nil
	}
	var rows []store.PanelInbound
	if err := b.st.DB().WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("clientcfg: read panel inbounds: %w", err)
	}
	index := make(map[inboundKey]string, len(rows))
	for _, row := range rows {
		index[inboundKey{kind: row.InboundKind, id: row.InboundID}] = row.Protocol
	}
	return index, nil
}

// protocolOf reports the protocol of an inbound. The AWG server falls back to
// its own kind, which the contract fixes; an xray inbound the panel did not
// list falls back to nothing rather than to a guess, because the field is
// informational and a wrong protocol is worse than none.
func (m material) protocolOf(kind string, id int64) string {
	if protocol := m.protocols[inboundKey{kind: kind, id: id}]; protocol != "" {
		return protocol
	}
	if kind == panel.InboundKindAWG {
		return panel.InboundKindAWG
	}
	return ""
}

// panelRevision returns the revision the input agrees on, or ErrRevisionMismatch
// when the two paths, or a path and the caller, disagree.
func (in Input) panelRevision() (string, error) {
	want := in.PanelRevision
	for _, configs := range []*panel.ProbeConfigs{in.Proxy, in.Direct} {
		if configs == nil || configs.Revision == "" {
			continue
		}
		if want == "" {
			want = configs.Revision
			continue
		}
		if configs.Revision != want {
			return "", fmt.Errorf("%w: %s and %s", ErrRevisionMismatch, want, configs.Revision)
		}
	}
	return want, nil
}

// probeFromSettings copies the probe parameter block out of the settings
// (spec §9.4, Probe tab).
func probeFromSettings(s store.Settings) Probe {
	return Probe{
		IntervalMs:         s.IntervalMs,
		BudgetMs:           s.BudgetMs,
		ConnectMs:          s.ConnectMs,
		TLSMs:              s.TLSMs,
		HeadersMs:          s.HeadersMs,
		StartJitterMs:      s.StartJitterMs,
		HeartbeatTimeoutMs: s.HeartbeatTimeoutMs,
	}
}

// buildOne assembles one mon-client's document, hashes it and stores it.
func (b *Builder) buildOne(ctx context.Context, mc store.MonClient, m material) (Result, error) {
	var (
		doc Document
		err error
	)
	if m.keepTargets {
		doc, err = b.documentKeepingTargets(ctx, mc, m)
	} else {
		doc, err = m.documentFor(mc)
	}
	if err != nil {
		return Result{}, err
	}
	revision, err := Revision(doc)
	if err != nil {
		return Result{}, err
	}
	doc.ConfigRevision = revision
	raw, err := marshalDocument(doc)
	if err != nil {
		return Result{}, err
	}

	previous, err := b.storedRevision(ctx, mc.ID)
	if err != nil {
		return Result{}, err
	}
	row := store.ClientConfig{
		MonClientID: mc.ID,
		Revision:    revision,
		Document:    string(raw),
		BuiltAt:     clock.MS(b.clk.Now()),
	}
	err = b.st.DB().WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "mon_client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"revision", "document", "built_at"}),
	}).Create(&row).Error
	if err != nil {
		return Result{}, fmt.Errorf("clientcfg: store config of %s: %w", mc.ID, err)
	}
	return Result{
		MonClientID: mc.ID,
		Revision:    revision,
		Previous:    previous,
		Changed:     previous != revision,
		Document:    json.RawMessage(raw),
	}, nil
}

// documentFor assembles the document of one mon-client, without its revision.
func (m material) documentFor(mc store.MonClient) (Document, error) {
	paths, err := store.DecodePaths(mc.Paths)
	if err != nil {
		return Document{}, fmt.Errorf("clientcfg: mon-client %s: %w", mc.ID, err)
	}
	targets := make([]DocumentTarget, 0, len(paths)*len(m.items[panel.PathDirect]))
	seen := make(map[Target]struct{})
	for _, path := range paths {
		for _, item := range m.items[path] {
			target := Target{InboundKind: item.Kind, InboundID: item.InboundID, Path: path}
			if _, dup := seen[target]; dup {
				continue
			}
			seen[target] = struct{}{}
			targets = append(targets, DocumentTarget{
				Target:   target,
				Protocol: m.protocolOf(item.Kind, item.InboundID),
				Link:     item.Link,
				Conf:     item.Conf,
			})
		}
	}
	sortTargets(targets)
	return Document{
		MonClientID: mc.ID,
		ProbeURL:    m.probeURL,
		Probe:       m.probe,
		Targets:     targets,
	}, nil
}

// documentKeepingTargets rebuilds mc's document around the targets it already
// has, refreshing only what comes from mon-server itself. Targets on a path
// the mon-client no longer probes are dropped: keeping them is the one way
// this rebuild could hand out something the panel material would not.
func (b *Builder) documentKeepingTargets(ctx context.Context, mc store.MonClient, m material) (Document, error) {
	raw, _, err := b.Document(ctx, mc.ID)
	if err != nil {
		return Document{}, err
	}
	var stored Document
	if err := json.Unmarshal(raw, &stored); err != nil {
		return Document{}, fmt.Errorf("clientcfg: parse stored config of %s: %w", mc.ID, err)
	}
	paths, err := store.DecodePaths(mc.Paths)
	if err != nil {
		return Document{}, fmt.Errorf("clientcfg: mon-client %s: %w", mc.ID, err)
	}
	allowed := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		allowed[path] = struct{}{}
	}
	targets := make([]DocumentTarget, 0, len(stored.Targets))
	for _, target := range stored.Targets {
		if _, ok := allowed[target.Path]; ok {
			targets = append(targets, target)
		}
	}
	sortTargets(targets)
	return Document{
		MonClientID: mc.ID,
		ProbeURL:    m.probeURL,
		Probe:       m.probe,
		Targets:     targets,
	}, nil
}

// sortTargets puts the targets in an order of mon-server's own choosing —
// inbound kind, inbound id, then path — so that the document, and with it the
// config revision, does not move when the panel returns the same probe set in
// another order. Nothing in the contract fixes the order of items, and a
// reshuffle must not send every mon-client back for a config it already has.
func sortTargets(targets []DocumentTarget) {
	sort.SliceStable(targets, func(i, j int) bool {
		a, b := targets[i], targets[j]
		switch {
		case a.InboundKind != b.InboundKind:
			return a.InboundKind < b.InboundKind
		case a.InboundID != b.InboundID:
			return a.InboundID < b.InboundID
		case pathRank(a.Path) != pathRank(b.Path):
			return pathRank(a.Path) < pathRank(b.Path)
		default:
			return a.Path < b.Path
		}
	})
}

// pathRank orders the paths within one inbound: proxy first, direct second, as
// protocol §4.2 spells them. Ranking rather than sorting the strings keeps the
// two paths in the order the specification shows, and keeps two mon-clients
// with the same set of paths written in a different order byte-identical.
func pathRank(path string) int {
	switch path {
	case panel.PathProxy:
		return 0
	case panel.PathDirect:
		return 1
	default:
		return 2
	}
}

// monClient reads one registry row.
func (b *Builder) monClient(ctx context.Context, id string) (store.MonClient, error) {
	var mc store.MonClient
	err := b.st.DB().WithContext(ctx).Where("id = ?", id).Take(&mc).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return store.MonClient{}, fmt.Errorf("%w: %s", ErrUnknownMonClient, id)
	case err != nil:
		return store.MonClient{}, fmt.Errorf("clientcfg: read mon-client %s: %w", id, err)
	}
	return mc, nil
}

// storedRevision is the revision currently in client_configs, empty when there
// is no row yet.
func (b *Builder) storedRevision(ctx context.Context, monClientID string) (string, error) {
	var row store.ClientConfig
	err := b.st.DB().WithContext(ctx).Select("revision").Where("mon_client_id = ?", monClientID).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("clientcfg: read stored revision of %s: %w", monClientID, err)
	}
	return row.Revision, nil
}
