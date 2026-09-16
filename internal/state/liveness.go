package state

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// LivenessInterval is how often the job of spec §7.3 looks for mon-clients
// that have stopped reporting. It is far shorter than the silence it detects,
// so a mon-client is declared offline within twenty seconds of the deadline
// rather than at the next heartbeat that never comes.
const LivenessInterval = 20 * time.Second

// Monitor is the job of spec §7.3: it watches last_heartbeat and moves a
// mon-client to OFFLINE once it has been silent for
// clientOfflineAfter × intervalMs + heartbeatTimeoutMs.
//
// The job is a loop around CheckOnce so that tests drive it a step at a time
// with a fake clock and never wait.
type Monitor struct {
	m        *Machine
	log      *slog.Logger
	interval time.Duration
}

// NewMonitor returns the liveness job of one Machine.
func NewMonitor(m *Machine) *Monitor {
	return &Monitor{m: m, log: m.log, interval: LivenessInterval}
}

// Run drives CheckOnce every LivenessInterval until ctx is cancelled. The
// wiring layer runs it in its own goroutine; a failed pass is logged and the
// next one tries again.
func (mo *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(mo.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := mo.CheckOnce(ctx); err != nil {
				mo.log.Error("mon-client liveness check failed", "error", err)
			}
		}
	}
}

// CheckOnce runs one pass of the liveness job (spec §7.3).
//
// A mon-client that has never reported stays NEVER: it has no last heartbeat
// to miss, and an approved box that has not been installed yet is not an
// outage. One that is ONLINE and has been silent past the deadline goes
// OFFLINE with a mon_client event carrying heartbeat_missed — the one thing
// the owner hears about — and all of its targets go to UNKNOWN with
// mon_client_offline, filed as events but announced by nobody: it is the
// mon-client that failed, not eight targets.
func (mo *Monitor) CheckOnce(ctx context.Context) error {
	m := mo.m
	m.mu.Lock()
	defer m.mu.Unlock()

	th, err := m.thresholds()
	if err != nil {
		return err
	}
	var clients []store.MonClient
	if err := m.st.DB().WithContext(ctx).
		Where("state = ?", store.ClientStateOnline).
		Order("id").Find(&clients).Error; err != nil {
		return fmt.Errorf("state: read mon-clients: %w", err)
	}

	now := m.nowMS()
	for i := range clients {
		mc := &clients[i]
		if mc.LastHeartbeat <= 0 {
			// ONLINE without a heartbeat time is not a judgement this job can
			// make; the next heartbeat repairs the row.
			continue
		}
		silence := now - mc.LastHeartbeat
		if silence <= th.offlineAfterMS {
			continue
		}
		missed := int(silence / th.intervalMS)
		mc.State = store.ClientStateOffline
		mc.MissedHeartbeats = missed
		if err := m.saveMonClient(ctx, mc); err != nil {
			return err
		}
		if err := m.file(ctx, []pendingEvent{loudEvent(
			events.MonClient(now, mc.ID, store.ClientStateOnline, store.ClientStateOffline, panel.ReasonHeartbeatMissed),
		)}); err != nil {
			return err
		}
		moved, err := m.resetToUnknown(ctx, mc.ID, panel.ReasonMonClientOffline)
		if err != nil {
			return err
		}
		mo.log.Info("mon-client offline",
			"monClientId", mc.ID, "silenceMs", silence, "missedHeartbeats", missed, "targetsReset", moved)
	}
	return nil
}
