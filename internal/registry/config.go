package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// revisionHexLen is how much of the SHA-256 a config revision keeps (spec
// §5, protocol §4.1: "первые 16 hex"). It is the same length the panel's own
// revision uses, which is not a coincidence: both are "did anything I care
// about change" fingerprints, not identifiers, and 64 bits is far more than
// enough to make an accidental collision between two consecutive documents
// impossible in practice.
const revisionHexLen = 16

// ErrNoConfig is Current's answer when this mon-client has no document yet
// and none can be built — which in practice means mon-server has never
// successfully read probe material from the panel (a fresh install, or one
// whose very first poll has not finished). internal/api turns it into
// `503 config_not_ready`: the mon-client should come back, not give up.
var ErrNoConfig = errors.New("registry: no config built yet")

// ProbeParams are the probe timings a mon-client runs its cycle by (spec
// §5, protocol §4.2), taken verbatim from the global settings an admin
// edits (spec §9.4). They are part of the config document — and therefore
// of the config revision — because changing one has to reach every
// mon-client; the state machine's thresholds deliberately are not, since
// only mon-server evaluates those.
type ProbeParams struct {
	IntervalMs         int64 `json:"intervalMs"`
	BudgetMs           int64 `json:"budgetMs"`
	ConnectMs          int64 `json:"connectMs"`
	TlsMs              int64 `json:"tlsMs"`
	HeadersMs          int64 `json:"headersMs"`
	StartJitterMs      int64 `json:"startJitterMs"`
	HeartbeatTimeoutMs int64 `json:"heartbeatTimeoutMs"`
}

// ConfigTarget is one (inbound, path) pair a mon-client probes (protocol
// §4.2). Link and Conf are the panel's own material copied verbatim — an
// xray subscription link for kind "xray", an AWG .conf for kind "awg" —
// because mon-server is deliberately transparent about protocols (protocol
// §4.2: knowing what a link means lives only in mon-client). Exactly one of
// them is ever set, which is why both are omitempty.
type ConfigTarget struct {
	InboundKind string `json:"inboundKind"`
	InboundID   int    `json:"inboundId"`
	Path        string `json:"path"`
	Protocol    string `json:"protocol"`
	Link        string `json:"link,omitempty"`
	Conf        string `json:"conf,omitempty"`
}

// ConfigDoc is the GET /v1/config document (protocol §4.2), field order and
// names exactly as the protocol shows them. It is what a mon-client turns
// into a running probe cycle, and the only thing about it mon-server ever
// compares is ConfigRevision.
type ConfigDoc struct {
	ConfigRevision string         `json:"configRevision"`
	MonClientID    string         `json:"monClientId"`
	ProbeURL       string         `json:"probeUrl"`
	Probe          ProbeParams    `json:"probe"`
	Targets        []ConfigTarget `json:"targets"`
}

// TargetKey names one target without describing it. It is comparable (so it
// works as a map key) precisely because the steps that consume it — the
// heartbeat's "is this result for a target I actually handed out" filter
// (step 6) and the tunnel probe's unknown-target flag (step 8) — need set
// membership, not the material.
type TargetKey struct {
	InboundKind string
	InboundID   int
	Path        string
}

// MaterialSource is where a ConfigBuilder gets the panel's probe material
// (spec §4 step 3). *panel.Poller satisfies it; the interface exists so the
// builder's own tests can drive it from a value instead of a live panel, and
// so registry never has to know how material is fetched.
type MaterialSource interface {
	Material() (panel.Material, bool)
}

// ConfigBuilder assembles and stores every mon-client's config document
// (spec §5). It holds no built state of its own: `client_configs` is the
// one place a document lives, so a restart, a second goroutine or the admin
// UI all see the same answer, and a rebuild is always a pure function of
// (material, mon-client row, settings, probeURL).
type ConfigBuilder struct {
	st       *store.Store
	clk      clock.Clock
	material MaterialSource
	probeURL string
}

// NewConfigBuilder wires a builder over st. probeURL is the address
// mon-clients send tunnel probes to (spec §5: "https://<publicIp>:<port>/v1/probe"),
// computed once by internal/app from bootstrap config — it cannot come from
// settings, because the listener it names is fixed at process start.
func NewConfigBuilder(st *store.Store, clk clock.Clock, material MaterialSource, probeURL string) *ConfigBuilder {
	return &ConfigBuilder{st: st, clk: clk, material: material, probeURL: probeURL}
}

// RebuildAll rebuilds every mon-client's document (panel.ConfigBuilder).
// The poller calls it on every accepted material change (spec §4 step 3),
// and step 10's Settings Save calls it when a probe parameter or realHost
// changes (spec §9.4). With no material yet it is a no-op rather than an
// error: a mon-server whose first poll has not landed simply has nothing to
// build from, and failing here would turn a normal cold start into a logged
// error every minute.
func (b *ConfigBuilder) RebuildAll(ctx context.Context) error {
	mat, ok := b.material.Material()
	if !ok {
		return nil
	}
	set, err := b.st.LoadSettings()
	if err != nil {
		return fmt.Errorf("registry: load settings: %w", err)
	}
	protocols, err := b.protocols(ctx)
	if err != nil {
		return err
	}

	var clients []store.MonClient
	if err := b.st.DB.WithContext(ctx).Order("id ASC").Find(&clients).Error; err != nil {
		return fmt.Errorf("registry: list mon-clients: %w", err)
	}
	for i := range clients {
		if _, err := b.buildAndStore(ctx, &clients[i], mat, set, protocols); err != nil {
			return err
		}
	}
	return nil
}

// Rebuild rebuilds one mon-client's document — the targeted counterpart of
// RebuildAll, for the two events that change exactly one document:
// Hooks.PathsChanged (an admin edited this client's paths) and
// Hooks.Approved (a new or replaced client that has no document yet). Like
// RebuildAll it is a no-op while there is no material.
func (b *ConfigBuilder) Rebuild(ctx context.Context, monClientID string) error {
	_, err := b.rebuild(ctx, monClientID)
	return err
}

// rebuild is Rebuild's body, returning the document it built (nil when
// there is no material) so Current can reuse it without a second read.
func (b *ConfigBuilder) rebuild(ctx context.Context, monClientID string) (*ConfigDoc, error) {
	mat, ok := b.material.Material()
	if !ok {
		return nil, nil
	}
	mc, err := b.client(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	set, err := b.st.LoadSettings()
	if err != nil {
		return nil, fmt.Errorf("registry: load settings: %w", err)
	}
	protocols, err := b.protocols(ctx)
	if err != nil {
		return nil, err
	}
	return b.buildAndStore(ctx, mc, mat, set, protocols)
}

// Current returns the mon-client's document for GET /v1/config (protocol
// §4.2). A mon-client approved between two panel revisions would otherwise
// have to wait for the next material change before it could configure
// itself at all, so a missing row is built on demand (and stored, so the
// revision it is told is the one every later comparison uses). ErrNoConfig
// means there is genuinely nothing to serve yet.
func (b *ConfigBuilder) Current(ctx context.Context, monClientID string) (*ConfigDoc, error) {
	row, err := b.row(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	if row != nil {
		var doc ConfigDoc
		if err := json.Unmarshal([]byte(row.Document), &doc); err != nil {
			return nil, fmt.Errorf("registry: decode stored config for %s: %w", monClientID, err)
		}
		return &doc, nil
	}

	doc, err := b.rebuild(ctx, monClientID)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, ErrNoConfig
	}
	return doc, nil
}

// CurrentRevision returns just the stored configRevision — what a heartbeat
// answer carries (protocol §5.3) and what the admin UI compares a
// mon-client's applied revision against (spec §9.3). It never builds: an
// empty string plus a nil error means "nothing built yet", which for a
// heartbeat is not an error but simply "no config to converge on".
func (b *ConfigBuilder) CurrentRevision(ctx context.Context, monClientID string) (string, error) {
	row, err := b.row(ctx, monClientID)
	if err != nil || row == nil {
		return "", err
	}
	return row.Revision, nil
}

// TargetKeys is the set of targets this mon-client was actually handed, in
// the document's own order — the filter step 6 drops heartbeat results for
// targets nobody asked for by, and the check step 8 marks a tunnel probe as
// unknown by. nil (with a nil error) means no document exists yet.
func (b *ConfigBuilder) TargetKeys(ctx context.Context, monClientID string) ([]TargetKey, error) {
	doc, err := b.Current(ctx, monClientID)
	if errors.Is(err, ErrNoConfig) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keys := make([]TargetKey, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		keys = append(keys, TargetKey{InboundKind: t.InboundKind, InboundID: t.InboundID, Path: t.Path})
	}
	return keys, nil
}

// buildAndStore builds one document and upserts it into client_configs.
// The whole document is stored, not just its parts, because GET /v1/config
// must answer the exact bytes the revision was computed over even if the
// material has moved on since (a mon-client fetching a config it was just
// told about must not silently get a newer one under the old revision).
func (b *ConfigBuilder) buildAndStore(ctx context.Context, mc *store.MonClient, mat panel.Material, set *store.Settings, protocols map[TargetKey]string) (*ConfigDoc, error) {
	doc, err := b.build(mc, mat, set, protocols)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("registry: encode config for %s: %w", mc.Id, err)
	}
	row := store.ClientConfig{
		MonClientId: mc.Id,
		Revision:    doc.ConfigRevision,
		Document:    string(raw),
		BuiltAt:     clock.Ms(b.clk.Now()),
	}
	if err := b.st.DB.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "mon_client_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"revision", "document", "built_at"}),
	}).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("registry: store config for %s: %w", mc.Id, err)
	}
	return doc, nil
}

// build assembles the document itself: spec §5's targets rule (every path
// of this mon-client crossed with that path's items, proxy only while the
// panel's override is on), the global probe parameters, the probe URL, and
// finally the revision over everything above.
func (b *ConfigBuilder) build(mc *store.MonClient, mat panel.Material, set *store.Settings, protocols map[TargetKey]string) (*ConfigDoc, error) {
	doc := &ConfigDoc{
		MonClientID: mc.Id,
		ProbeURL:    b.probeURL,
		Probe: ProbeParams{
			IntervalMs:         set.IntervalMs,
			BudgetMs:           set.BudgetMs,
			ConnectMs:          set.ConnectMs,
			TlsMs:              set.TlsMs,
			HeadersMs:          set.HeadersMs,
			StartJitterMs:      set.StartJitterMs,
			HeartbeatTimeoutMs: set.HeartbeatTimeoutMs,
		},
		Targets: []ConfigTarget{},
	}

	for _, path := range pathsOf(mc) {
		for _, item := range itemsFor(mat, path) {
			key := TargetKey{InboundKind: item.Kind, InboundID: item.InboundId, Path: path}
			doc.Targets = append(doc.Targets, ConfigTarget{
				InboundKind: item.Kind,
				InboundID:   item.InboundId,
				Path:        path,
				Protocol:    protocolOf(key, protocols),
				// Verbatim (spec §5): the panel has already rendered the
				// right host for this path, so any rewriting here could
				// only introduce a way to get it wrong.
				Link: item.Link,
				Conf: item.Conf,
			})
		}
	}
	// A stable order is what makes the revision a function of content
	// rather than of the order two paths happened to be iterated in.
	slices.SortFunc(doc.Targets, func(x, y ConfigTarget) int {
		if c := strings.Compare(x.InboundKind, y.InboundKind); c != 0 {
			return c
		}
		if x.InboundID != y.InboundID {
			return x.InboundID - y.InboundID
		}
		return strings.Compare(x.Path, y.Path)
	})

	rev, err := revisionOf(doc)
	if err != nil {
		return nil, err
	}
	doc.ConfigRevision = rev
	return doc, nil
}

// pathsOf is spec §5's default: a mon-client with no paths stored (or an
// unreadable column) probes both.
func pathsOf(mc *store.MonClient) []string {
	paths := mc.PathsList()
	if len(paths) == 0 {
		return []string{store.PathProxy, store.PathDirect}
	}
	return paths
}

// itemsFor picks the material for one path. The proxy path exists only
// while the panel's host override is on (spec §5): with it off there is no
// proxy front to render configs for, and the poller will not even have
// fetched any — checking here as well keeps a mon-client that asks for the
// proxy path from silently getting the direct material.
func itemsFor(mat panel.Material, path string) []panel.ProbeItem {
	switch path {
	case store.PathProxy:
		if !mat.Override.Enabled {
			return nil
		}
		return mat.Proxy
	case store.PathDirect:
		return mat.Direct
	default:
		// validatePaths rejects anything else before it can ever be stored;
		// this is the belt to that braces.
		return nil
	}
}

// protocolOf answers the document's `protocol` field (protocol §4.2). AWG
// has no protocol of its own in the panel's inbound list, so it is spelled
// "awg" — the same string the kind uses — rather than left empty. An xray
// inbound mon-server has not yet seen in GET /state yields "", which is
// honest: the field is informational for the admin UI and mon-client's
// logs, and inventing a protocol would be worse than admitting we have not
// been told one.
func protocolOf(key TargetKey, protocols map[TargetKey]string) string {
	if key.InboundKind == store.InboundKindAwg {
		return store.InboundKindAwg
	}
	return protocols[TargetKey{InboundKind: key.InboundKind, InboundID: key.InboundID}]
}

// protocols reads panel_inbounds into the (kind, inboundId) → protocol map
// build joins on. It is read once per rebuild rather than per target so a
// registry with a hundred mon-clients does not issue a query per target.
func (b *ConfigBuilder) protocols(ctx context.Context) (map[TargetKey]string, error) {
	var rows []store.PanelInbound
	if err := b.st.DB.WithContext(ctx).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("registry: read panel_inbounds: %w", err)
	}
	out := make(map[TargetKey]string, len(rows))
	for _, r := range rows {
		out[TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundId}] = r.Protocol
	}
	return out, nil
}

// client loads one mon-client row, mapping "no such row" onto the same
// ErrClientNotFound every other registry operation uses.
func (b *ConfigBuilder) client(ctx context.Context, id string) (*store.MonClient, error) {
	var mc store.MonClient
	if err := b.st.DB.WithContext(ctx).First(&mc, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return &mc, nil
}

// row loads the stored config for a mon-client, returning (nil, nil) when
// there is none — "not built yet" is an ordinary state here (see Current
// and CurrentRevision), not an error each caller should have to translate.
func (b *ConfigBuilder) row(ctx context.Context, monClientID string) (*store.ClientConfig, error) {
	var row store.ClientConfig
	err := b.st.DB.WithContext(ctx).First(&row, "mon_client_id = ?", monClientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("registry: read client_configs for %s: %w", monClientID, err)
	}
	return &row, nil
}

// revisionOf computes spec §5's config revision: the first revisionHexLen
// hex characters of SHA-256 over the canonical JSON of the document without
// its own configRevision field. Hashing the document rather than its inputs
// is what makes the rule "the revision changes exactly when what the
// mon-client is told changes" true by construction — a panel revision that
// only renamed an inbound's remark produces byte-identical documents and
// therefore no re-fetch (protocol §4.3: a new revision costs an xray
// restart on every mon-client).
func revisionOf(doc *ConfigDoc) (string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("registry: encode config document: %w", err)
	}
	canon, err := canonicalJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])[:revisionHexLen], nil
}

// canonicalJSON re-encodes a document as the revision's input: decoded into
// map[string]any and marshalled again, which Go's encoder emits with object
// keys sorted and no whitespace, and with the configRevision field dropped.
// Round-tripping through a map (rather than hashing the struct's own
// marshalling) is what makes the hash independent of Go struct field order
// and of any future field reordering in ConfigDoc, so two mon-servers on
// different builds agree on a revision for the same document.
func canonicalJSON(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("registry: canonicalise config document: %w", err)
	}
	delete(m, "configRevision")
	canon, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("registry: canonicalise config document: %w", err)
	}
	return canon, nil
}

// snapshotSource adapts the registry to panel.SnapshotSource — see
// (*Registry).SnapshotSource.
type snapshotSource struct{ r *Registry }

// Snapshot maps every registry row onto the panel's own mon-client shape
// (contract §4.3). A mon-client that has never heartbeated has a NULL
// last_heartbeat, which the contract spells as 0: the panel's UI reads
// State ("NEVER") for that case, and a pointer would only give it a second
// way to express the same thing.
func (s snapshotSource) Snapshot(ctx context.Context) ([]panel.MonClientSnapshot, error) {
	clients, err := s.r.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]panel.MonClientSnapshot, 0, len(clients))
	for _, mc := range clients {
		var last int64
		if mc.LastHeartbeat != nil {
			last = *mc.LastHeartbeat
		}
		out = append(out, panel.MonClientSnapshot{
			Id:            mc.Id,
			Name:          mc.Name,
			Region:        mc.Region,
			State:         mc.State,
			LastHeartbeat: last,
		})
	}
	return out, nil
}

// SnapshotSource returns the registry as the poller's snapshot source (spec
// §4 step 2). It is an adapter rather than a method on Registry itself
// because Registry.Snapshot returns store rows — what the admin UI and the
// rest of registry want — and only the poller needs them in the panel's
// wire shape.
func (r *Registry) SnapshotSource() panel.SnapshotSource {
	return snapshotSource{r: r}
}
