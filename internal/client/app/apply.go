package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/awg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
)

// ProvisionalApplier is step 7's stand-in for the real config applier
// (step 8, spec §4.3). It does the half of applying a revision that the
// probe cycle cannot be tested without — parse the document's targets into
// the probe.Fn map the Runner drives, and record appliedRevision in
// state.json — and deliberately does NOT do the other half: it never
// writes xray.json, never runs `xray -test`, and never starts or restarts
// the xray child.
//
// That means an xray-target's probe dials a socks port nothing is
// listening on until step 8 lands, and its result is a truthful
// tcp_refused. The alternative — wiring the loop to no applier at all —
// would have left the whole cycle → heartbeat path unexercised end to end
// in cmd/mon-client, which is the one thing step 7 exists to deliver.
//
// Step 8 replaces this type with the real one. It must keep the Applier
// contract documented on that interface; the probe-building here (a socks
// port per xray-target from config.BuildXray, an AWG config per
// awg-target) is the part worth carrying over.
type ProvisionalApplier struct {
	xray *probe.Prober
	awg  *awg.Prober
	dir  *state.Dir
	log  *slog.Logger

	mu      sync.Mutex
	file    *state.File
	doc     *proto.ConfigDoc
	probes  map[proto.TargetKey]probe.Fn
	lastErr error
}

// NewProvisionalApplier wires the applier to the probers it builds Fns
// from and to the state file whose appliedRevision it maintains. file is
// the same *state.File the Loop reads its configRevision from — the
// applier is the only writer of AppliedRevision, and the loop the only
// reader, which is what keeps "what I probe" and "what I claim to probe"
// in step (protocol §5.3).
func NewProvisionalApplier(xrayProber *probe.Prober, awgProber *awg.Prober, dir *state.Dir, file *state.File, log *slog.Logger) *ProvisionalApplier {
	if log == nil {
		log = slog.Default()
	}
	if xrayProber == nil {
		xrayProber = &probe.Prober{Logger: log}
	}
	if awgProber == nil {
		awgProber = &awg.Prober{Log: log}
	}
	return &ProvisionalApplier{xray: xrayProber, awg: awgProber, dir: dir, file: file, log: log}
}

// Apply builds one probe.Fn per target of doc and, if every target parsed,
// records doc as applied (appliedRevision in state.json, spec §4.3).
//
// A document that will not parse leaves the previous one in force and
// comes back as the error the loop sends as configError — the same rule
// step 8 has to keep, just without the xray restart that can also fail.
func (a *ProvisionalApplier) Apply(_ context.Context, doc *proto.ConfigDoc) error {
	probes, err := a.build(doc)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		return err
	}

	a.mu.Lock()
	a.doc, a.probes, a.lastErr = doc, probes, nil
	file := *a.file
	a.mu.Unlock()

	if file.AppliedRevision == doc.ConfigRevision {
		return nil
	}
	file.AppliedRevision = doc.ConfigRevision
	if a.dir != nil {
		if err := a.dir.Save(&file); err != nil {
			return fmt.Errorf("app: save applied revision: %w", err)
		}
	}
	a.mu.Lock()
	*a.file = file
	a.mu.Unlock()
	return nil
}

// Applied reports the document the box is currently probing by, its probe
// map and the configError (see the Applier contract).
func (a *ProvisionalApplier) Applied() (*proto.ConfigDoc, map[proto.TargetKey]probe.Fn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.doc, a.probes, a.lastErr
}

// build turns a document's targets into probes: xray-targets through the
// socks ports config.BuildXray assigns them (the ports step 8's generated
// xray.json will actually listen on), awg-targets through their parsed
// .conf. A target whose material does not parse fails the whole apply,
// exactly as spec §4.3 requires.
func (a *ProvisionalApplier) build(doc *proto.ConfigDoc) (map[proto.TargetKey]probe.Fn, error) {
	probes := map[proto.TargetKey]probe.Fn{}
	if doc == nil {
		return probes, nil
	}

	budgets := probe.BudgetsFrom(doc.Probe)
	token := a.token()

	targets := make([]config.Target, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		targets = append(targets, config.Target{
			InboundKind: t.InboundKind,
			InboundID:   t.InboundID,
			Path:        t.Path,
			Protocol:    t.Protocol,
			Link:        t.Link,
			Conf:        t.Conf,
		})
	}

	_, plans, err := config.BuildXray(targets, config.FirstSocksPort)
	if err != nil {
		return nil, err
	}
	for _, plan := range plans {
		key := proto.TargetKey(plan.Key)
		probes[key] = func(ctx context.Context, k proto.TargetKey) proto.Result {
			// The diagnoser is nil until step 8 owns the xray child: with
			// no child there is no stderr to read, and probe.Prober
			// documents nil as "classify the failure without a second
			// opinion".
			return a.xray.Xray(ctx, doc.ProbeURL, token, k, plan, budgets, nil)
		}
	}

	for _, t := range doc.Targets {
		if t.Conf == "" {
			continue
		}
		cfg, err := config.ParseAWGConf(t.Conf)
		if err != nil {
			return nil, fmt.Errorf("app: target %s: %w", t.TargetKey, err)
		}
		probes[t.TargetKey] = func(ctx context.Context, k proto.TargetKey) proto.Result {
			return a.awg.Probe(ctx, doc.ProbeURL, token, k, cfg, budgets)
		}
	}
	return probes, nil
}

// token is the client token every probe carries (protocol §5.2), read
// under the lock because the applier shares its *state.File with the loop.
func (a *ProvisionalApplier) token() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return ""
	}
	return a.file.Token
}
