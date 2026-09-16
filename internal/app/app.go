// Package app assembles mon-server out of its packages and runs it.
//
// Every package underneath is written to know nothing about the others: the
// API layer declares the services it needs, the admin UI declares its ports,
// the panel poll takes its four seams as function values. This package is the
// one place that holds all of them at once, which is why it is also the only
// place that has to change when a dependency moves.
package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/admin"
	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clientcfg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/dispatch"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/retention"
	"github.com/SBKubric/3ax-ui-monitoring/internal/server"
	"github.com/SBKubric/3ax-ui-monitoring/internal/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/stats"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tlsx"
)

// shutdownGrace bounds how long a stop waits for handlers already running.
// mon-server's handlers are short: a heartbeat writes a few rows, a tunnel
// probe answers immediately.
const shutdownGrace = 20 * time.Second

// certificateRetry is how long a failed certificate acquisition waits before
// trying again. The listener keeps serving meanwhile, so the box is reachable
// on /healthz and the admin UI even while the certificate is missing.
const certificateRetry = time.Minute

// Options are what main hands over: the bootstrap configuration, the build
// version for the admin UI, and the logger.
type Options struct {
	Config  config.Config
	Version string
	Log     *slog.Logger
	Clock   clock.Clock
}

// App is a configured mon-server. New builds it, Run serves until the context
// is cancelled, Close releases what New opened.
type App struct {
	cfg     config.Config
	version string
	log     *slog.Logger
	clk     clock.Clock

	store    *store.Store
	tls      *tlsx.Provider
	server   *server.Server
	registry *registry.Registry
	configs  *clientcfg.Builder
	machine  *state.Machine
	monitor  *state.Monitor
	recorder *stats.Recorder
	janitor  *retention.Janitor
	alert    alert.Func

	// httpClient is shared by the panel client, the Telegram sender and the
	// admin UI's Check button, so connections are reused instead of a new
	// transport appearing every cycle.
	httpClient *http.Client

	// The panel client is rebuilt whenever the panel address or the token
	// changes in the admin UI, so a correction takes effect without a
	// restart. The poller is kept across cycles: its three-strike counter and
	// its alert suppression are in memory, and resetting them every minute
	// would mean never declaring the panel down.
	pollMu      sync.Mutex
	poller      *panel.Poller
	pollerURL   string
	pollerToken string

	// pollNow asks the poll loop to run a cycle at once instead of waiting for
	// the next minute. Approving a mon-client or changing its paths should
	// take effect immediately, not on the next tick.
	pollNow chan struct{}
	// rebuildWanted records that mon-server's own state made the stored
	// configurations stale, so the next cycle must refetch the probe material
	// even though the panel's revision has not moved. It is cleared once a
	// rebuild has actually run.
	rebuildWanted atomic.Bool
}

// New opens the database and builds every component. It performs no network
// access: the listener is bound but not served, and no certificate is
// requested, until Run.
func New(o Options) (*App, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.Clock == nil {
		o.Clock = clock.System{}
	}
	if err := o.Config.Validate(); err != nil {
		return nil, err
	}

	a := &App{
		cfg:        o.Config,
		version:    o.Version,
		log:        o.Log,
		clk:        o.Clock,
		httpClient: &http.Client{Timeout: panel.DefaultTimeout},
		pollNow:    make(chan struct{}, 1),
	}

	st, err := store.Open(o.Config.DBPath(), o.Log, store.WithClock(o.Clock))
	if err != nil {
		return nil, err
	}
	a.store = st

	a.alert = telegramAlert(st, a.httpClient, o.Log)
	outbox := events.New(st, a.alert)

	a.registry = registry.New(st, outbox, o.Log)
	a.configs = clientcfg.New(st,
		clientcfg.WithProbeEndpoint(o.Config.Listen, o.Config.PublicIP),
		clientcfg.WithClock(o.Clock),
		clientcfg.WithLogger(o.Log),
	)
	a.recorder = stats.New(st, o.Clock, o.Log)
	a.machine = state.New(st, o.Clock, a.alert, o.Log, state.WithStatsSink(a.recorder))
	a.monitor = state.NewMonitor(a.machine)
	a.janitor = retention.New(st, o.Log)

	apiServer := api.New(a.registry, o.Clock, o.Log)
	api.RegisterRegistrationRoutes(apiServer, a.registry)
	api.RegisterConfigRoutes(apiServer, a.configs)
	api.RegisterHeartbeatRoutes(apiServer, a.machine)
	// The probe endpoint decides membership from the stored config document,
	// which is the same set the builder serves, so it needs no second source.
	api.RegisterProbeRoutes(apiServer, api.NewProbeStore(st, nil))

	adminServer, err := a.newAdmin()
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	provider, err := tlsx.New(tlsx.Options{
		Mode:     tlsx.Mode(o.Config.TLS.Mode),
		PublicIP: o.Config.PublicIP,
		CertsDir: o.Config.CertsDir(),
		CertFile: o.Config.TLS.Cert,
		KeyFile:  o.Config.TLS.Key,
		Log:      o.Log,
	})
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	a.tls = provider

	srv, err := server.New(server.Options{
		Addr:      o.Config.Listen,
		TLSConfig: provider.TLSConfig(),
		V1:        apiServer.Handler(),
		Admin:     adminServer.Handler(),
		Log:       o.Log,
		Clock:     o.Clock,
	})
	if err != nil {
		_ = provider.Close()
		_ = st.Close()
		return nil, err
	}
	a.server = srv
	return a, nil
}

// newAdmin builds the admin UI with the adapters onto the other packages.
func (a *App) newAdmin() (*admin.Server, error) {
	notAfter := a.certificateNotAfter()
	return admin.New(admin.Options{
		Store:    a.store,
		Registry: registryPort{reg: a.registry, cfg: a.configs, onRegistryChange: a.requestRebuild},
		Panel:    panelCheckPort{httpClient: a.httpClient, clock: a.clk, log: a.log},
		Telegram: telegramPort{httpClient: a.httpClient, log: a.log},
		Configs:  rebuildPort{cfg: a.configs, log: a.log},
		Clock:    a.clk,
		Log:      a.log,
		// The Requests page prints these in its header, so they have to be
		// the limits the registry actually enforces, not a second copy.
		RateLimits: admin.RateLimits{
			PerIPPerMinute: 1,
			PendingPerIP:   registry.MaxPendingPerIP,
			PendingGlobal:  registry.MaxPendingTotal,
		},
		Server: admin.ServerInfo{
			PublicIP:     a.cfg.PublicIP,
			Version:      a.version,
			TLSMode:      a.cfg.TLS.Mode,
			Listen:       a.cfg.Listen,
			DataDir:      a.cfg.DataDir,
			CertNotAfter: notAfter,
		},
	})
}

// certificateNotAfter reports when the served certificate expires, in ms UTC,
// or zero when that is not known. In files mode it is read from the supplied
// certificate; in acme-ip mode the certificate may not exist yet, and the
// admin UI shows the field as unknown rather than guessing.
func (a *App) certificateNotAfter() int64 {
	if a.cfg.TLS.Mode != config.TLSModeFiles || a.cfg.TLS.Cert == "" {
		return 0
	}
	pemBytes, err := os.ReadFile(a.cfg.TLS.Cert)
	if err != nil {
		return 0
	}
	leaf, err := firstCertificate(pemBytes)
	if err != nil {
		return 0
	}
	return clock.MS(leaf.NotAfter)
}

// Addr is the address the listener bound, useful when Listen asked for port
// zero.
func (a *App) Addr() string {
	if a.server == nil {
		return ""
	}
	return a.server.Addr()
}

// Run serves until ctx is cancelled or the listener fails, then shuts down
// gracefully. It starts the background loops of the spec: the panel poll every
// minute (§4), the mon-client liveness check every twenty seconds (§7.3) and
// the retention sweep every hour (§3).
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	serveErr := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		serveErr <- a.server.Serve(ctx)
	}()

	// The certificate is acquired only once the listener is up: the challenge
	// that proves the address is ours is answered on this very port.
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.manageCertificate(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		a.monitor.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.janitor.Run(ctx); err != nil {
			a.log.Error("retention stopped", "err", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		a.runPanelPoll(ctx)
	}()

	a.log.Info("mon-server is running",
		"listen", a.Addr(), "tls", a.cfg.TLS.Mode, "data_dir", a.cfg.DataDir, "version", a.version)

	var err error
	select {
	case <-ctx.Done():
	case err = <-serveErr:
		if err != nil {
			a.log.Error("the listener stopped", "err", err)
		}
	}

	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer stopCancel()
	if shutErr := a.server.Shutdown(stopCtx); shutErr != nil && err == nil {
		err = shutErr
	}
	wg.Wait()
	return err
}

// Close releases what New opened. It is safe after Run has returned.
func (a *App) Close() error {
	var errs []error
	if a.tls != nil {
		errs = append(errs, a.tls.Close())
	}
	if a.store != nil {
		errs = append(errs, a.store.Close())
	}
	return errors.Join(errs...)
}

// manageCertificate obtains and renews the certificate in acme-ip mode. A
// failure is not fatal: the box may be booting before its address is routable,
// or the certificate authority may be down. The listener keeps serving and the
// attempt is repeated, with the owner told once per failure.
func (a *App) manageCertificate(ctx context.Context) {
	for {
		err := a.tls.Manage(ctx)
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			return
		}
		a.log.Error("could not obtain the TLS certificate, retrying",
			"err", err, "retry_in", certificateRetry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(certificateRetry):
		}
	}
}

// runPanelPoll runs the once-a-minute cycle of spec §4.
func (a *App) runPanelPoll(ctx context.Context) {
	ticker := time.NewTicker(panel.PollInterval)
	defer ticker.Stop()

	a.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollOnce(ctx)
		case <-a.pollNow:
			a.pollOnce(ctx)
		}
	}
}

// requestRebuild marks the stored configurations stale and wakes the poll loop.
// It is called when the registry changes in a way the panel cannot see: a
// mon-client approved between two panel revisions has no configuration at all,
// and one whose paths were edited has the wrong one.
func (a *App) requestRebuild() {
	a.rebuildWanted.Store(true)
	select {
	case a.pollNow <- struct{}{}:
	default: // a cycle is already queued, which is all this needs
	}
}

// needsRebuild is the poller's seam for "refetch even though the revision has
// not moved". It answers yes when something asked for it, and also whenever an
// enabled mon-client has no configuration document: that condition is derived
// from the database rather than remembered, so it survives a restart.
func (a *App) needsRebuild(ctx context.Context) (bool, error) {
	if a.rebuildWanted.Load() {
		return true, nil
	}
	var missing int64
	err := a.store.DB().WithContext(ctx).
		Model(&store.MonClient{}).
		Where("enabled = ?", true).
		Where("id NOT IN (?)", a.store.DB().Model(&store.ClientConfig{}).Select("mon_client_id")).
		Count(&missing).Error
	if err != nil {
		return false, fmt.Errorf("app: count mon-clients without a config: %w", err)
	}
	return missing > 0, nil
}

// snapshot is the registry snapshot POST /probe/ensure carries, capped at the
// contract's limit. Over it the panel refuses the whole request, which would
// stop the probe accounts being maintained at all, so a too-large registry
// loses its tail with a loud log rather than losing the call.
func (a *App) snapshot(ctx context.Context) ([]panel.MonClientSnapshot, error) {
	all, err := a.registry.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(all) <= panel.MaxMonClients {
		return all, nil
	}
	a.log.Error("the registry is larger than the panel contract allows, the snapshot is truncated",
		"mon_clients", len(all), "limit", panel.MaxMonClients)
	return all[:panel.MaxMonClients], nil
}

// pollOnce runs one cycle against the panel currently configured.
func (a *App) pollOnce(ctx context.Context) {
	poller, err := a.currentPoller()
	switch {
	case errors.Is(err, errNoPanelSettings):
		a.log.Debug("skipping the panel poll: the panel is not configured yet")
		return
	case err != nil:
		a.log.Error("cannot build the panel client", "err", err)
		return
	}
	if err := poller.PollOnce(ctx); err != nil && ctx.Err() == nil {
		a.log.Warn("the panel poll cycle reported problems", "err", err)
	}
}

// currentPoller returns the poller for the panel address and token in the
// settings right now, rebuilding it when either has changed.
func (a *App) currentPoller() (*panel.Poller, error) {
	settings, err := a.store.Settings()
	if err != nil {
		return nil, fmt.Errorf("app: read settings: %w", err)
	}

	a.pollMu.Lock()
	defer a.pollMu.Unlock()
	if a.poller != nil && a.pollerURL == settings.PanelURL && a.pollerToken == settings.MonToken {
		return a.poller, nil
	}

	client, err := panelClientFor(settings, a.httpClient, a.clk, a.log)
	if err != nil {
		a.poller, a.pollerURL, a.pollerToken = nil, "", ""
		return nil, err
	}

	dispatcher, err := dispatch.New(dispatch.Options{
		Store: a.store,
		Panel: client,
		Stats: a.recorder,
		Clock: a.clk,
		Log:   a.log,
	})
	if err != nil {
		return nil, fmt.Errorf("app: dispatcher: %w", err)
	}

	poller, err := panel.NewPoller(panel.PollOptions{
		Client:       client,
		Store:        a.store,
		Outbox:       events.New(a.store, a.alert),
		Alert:        a.alert,
		Clock:        a.clk,
		Log:          a.log,
		Snapshot:     a.snapshot,
		Rebuild:      a.rebuildConfigs,
		Reconcile:    a.reconcileTargets,
		Dispatch:     dispatcher.Dispatch,
		NeedsRebuild: a.needsRebuild,
	})
	if err != nil {
		return nil, fmt.Errorf("app: poller: %w", err)
	}

	if a.pollerURL != "" && a.pollerURL != settings.PanelURL {
		a.log.Info("the panel address changed, the poll starts over", "panel_url", settings.PanelURL)
	}
	a.poller, a.pollerURL, a.pollerToken = poller, settings.PanelURL, settings.MonToken
	return poller, nil
}

// rebuildConfigs is the poll's Rebuild seam: new probe material means every
// mon-client's document is rebuilt, and those whose content actually moved get
// a new config revision.
func (a *App) rebuildConfigs(ctx context.Context, cfgs map[string]panel.ProbeConfigs) error {
	results, err := a.configs.RebuildAll(ctx, probeConfigs(cfgs))
	if err != nil {
		return err
	}
	// Cleared only now: a cycle that failed before reaching this point must
	// leave the request standing so the next one still refetches.
	a.rebuildWanted.Store(false)
	changed := 0
	for _, r := range results {
		if r.Changed {
			changed++
		}
	}
	if changed > 0 {
		a.log.Info("rebuilt mon-client configs", "mon_clients", len(results), "revisions_changed", changed)
	}
	return nil
}

// reconcileTargets is the poll's Reconcile seam: it brings each mon-client's
// target rows in line with the config it was just handed, creating rows for
// new targets and pausing the ones whose inbound the panel disabled or
// removed. Nothing else creates target rows, so a heartbeat about a target
// that was never reconciled is discarded by design.
func (a *App) reconcileTargets(ctx context.Context, _ []panel.Inbound, _ map[string]panel.ProbeConfigs) error {
	clients, err := a.registry.List(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range clients {
		targets, err := a.configs.Targets(ctx, c.ID)
		if err != nil {
			if errors.Is(err, clientcfg.ErrNoConfig) {
				continue
			}
			errs = append(errs, fmt.Errorf("targets of %s: %w", c.ID, err))
			continue
		}
		wanted := make([]state.TargetKey, 0, len(targets))
		for _, t := range targets {
			wanted = append(wanted, state.TargetKey(t))
		}
		if err := a.machine.SyncTargets(ctx, c.ID, wanted); err != nil {
			errs = append(errs, fmt.Errorf("sync targets of %s: %w", c.ID, err))
		}
	}
	return errors.Join(errs...)
}

// firstCertificate parses the leaf out of a PEM chain.
func firstCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := decodePEM(pemBytes)
	if block == nil {
		return nil, errors.New("app: no PEM block in the certificate file")
	}
	return x509.ParseCertificate(block)
}
