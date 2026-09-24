package admin

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// clientView is one registry row as the mon-clients page shows it (spec
// §9.3). Deliberately absent: anything about target state — the panel's
// Monitoring page owns that, and spec §9.3 is explicit that "состояние
// targets не показывается".
type clientView struct {
	Id     string   `json:"id"`
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`

	Enabled       bool   `json:"enabled"`
	State         string `json:"state"`
	LastHeartbeat *int64 `json:"lastHeartbeat"`
	ApprovedAt    int64  `json:"approvedAt"`

	Version     string `json:"version"`
	XrayVersion string `json:"xrayVersion"`

	// AppliedRevision is the config revision this mon-client last reported
	// applying; ServerRevision is the one mon-server has built for it. The
	// two differing is how the Edit modal shows a mon-client lagging behind
	// (spec §9.3: "применённая и серверная ревизии").
	AppliedRevision string `json:"appliedRevision"`
	ServerRevision  string `json:"serverRevision"`

	// ConfigError is the full text the box reported (spec §9.3: "полный
	// текст configError" in the modal; the table shows a ⚠ tag).
	ConfigError   string `json:"configError"`
	ConfigErrorAt *int64 `json:"configErrorAt"`
	// RejectedTargets are the targets the box rejected from its applied
	// revision, each with the box's error (protocol §5.3
	// client.rejectedTargets). This is the box's report about its config,
	// not target state: the PAUSED config_error they cause is the panel's to
	// show.
	RejectedTargets []store.RejectedTarget `json:"rejectedTargets"`

	RemoteIp string `json:"remoteIp"`
	// TokenRevoked marks a row whose token was revoked and that is waiting
	// for a new registration request to be approved as its replacement
	// (spec §6).
	TokenRevoked bool `json:"tokenRevoked"`
}

// listClients answers the mon-clients page (spec §9.3) with every registry
// row plus the config revision mon-server currently holds for it.
func (h *Handler) listClients(c *gin.Context) {
	ctx := c.Request.Context()

	clients, err := h.deps.Registry.List(ctx)
	if err != nil {
		slog.Error("admin: listing mon-clients failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not list mon-clients.")
		return
	}

	views := make([]clientView, 0, len(clients))
	for i := range clients {
		mc := &clients[i]
		v := clientView{
			Id:              mc.Id,
			Name:            mc.Name,
			Region:          mc.Region,
			Paths:           pathsOrDefault(mc),
			Enabled:         mc.Enabled,
			State:           mc.State,
			LastHeartbeat:   mc.LastHeartbeat,
			ApprovedAt:      mc.ApprovedAt,
			Version:         mc.Version,
			XrayVersion:     mc.XrayVersion,
			AppliedRevision: mc.AppliedRevision,
			ConfigError:     mc.ConfigError,
			ConfigErrorAt:   mc.ConfigErrorAt,
			RejectedTargets: mc.RejectedList(),
			RemoteIp:        mc.RemoteIp,
			TokenRevoked:    mc.TokenHash == "",
		}
		if v.RejectedTargets == nil {
			v.RejectedTargets = []store.RejectedTarget{}
		}
		if h.deps.Configs != nil {
			rev, err := h.deps.Configs.CurrentRevision(ctx, mc.Id)
			if err != nil {
				// A missing revision is normal (no panel material yet);
				// a failing one is worth a log line but must not take the
				// whole page down.
				slog.Warn("admin: reading a mon-client's config revision failed", "monClientId", mc.Id, "err", err)
			}
			v.ServerRevision = rev
		}
		views = append(views, v)
	}

	ok(c, gin.H{"clients": views, "now": clock.Ms(h.deps.Clock.Now())})
}

// updateBody is the Edit modal's submission (spec §9.3): name, region and
// paths are editable, the id is not — it is the slug the mon-client was
// approved under and every event, bucket and config document is keyed by it.
type updateBody struct {
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`
}

// updateClient applies the Edit modal. Changing paths bumps this
// mon-client's config revision through the registry's PathsChanged hook
// (step 5); changing only name or region does not, since neither appears in
// the config document.
func (h *Handler) updateClient(c *gin.Context) {
	var body updateBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed mon-client update.")
		return
	}
	if body.Name == "" {
		fail(c, http.StatusBadRequest, "Name is required.")
		return
	}
	if err := h.deps.Registry.Update(c.Request.Context(), c.Param("id"), body.Name, body.Region, body.Paths); err != nil {
		failRegistry(c, err, "Could not update the mon-client.")
		return
	}
	okMsg(c, "Saved.", nil)
}

// enabledBody is the Enabled switch's submission (spec §9.3).
type enabledBody struct {
	Enabled bool `json:"enabled"`
}

// setClientEnabled flips the switch. Disabling drives this mon-client's
// targets to UNKNOWN with reason mon_client_disabled (spec §6, through the
// registry's Disabled hook) but keeps the row in the panel's snapshot;
// enabling simply lets its heartbeats start succeeding again.
func (h *Handler) setClientEnabled(c *gin.Context) {
	var body enabledBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed request.")
		return
	}
	if err := h.deps.Registry.SetEnabled(c.Request.Context(), c.Param("id"), body.Enabled); err != nil {
		failRegistry(c, err, "Could not change the mon-client.")
		return
	}
	if body.Enabled {
		okMsg(c, "Enabled.", nil)
		return
	}
	okMsg(c, "Disabled. Its targets go to UNKNOWN until it is enabled again.", nil)
}

// revokeClient invalidates the token but keeps the row (spec §6): the box
// gets 401 on its next call, wipes its state and registers again, and that
// new request can be approved as this row's replacement to bring the id
// back.
func (h *Handler) revokeClient(c *gin.Context) {
	if err := h.deps.Registry.Revoke(c.Request.Context(), c.Param("id")); err != nil {
		failRegistry(c, err, "Could not revoke the token.")
		return
	}
	okMsg(c, "Token revoked. The box will register again; approve that request as a replacement to keep this id.", nil)
}

// deleteClient removes the row and its targets outright (spec §6). Unlike
// Revoke there is nothing left for a replacement to attach to — the panel
// drops its own copy on the next snapshot.
func (h *Handler) deleteClient(c *gin.Context) {
	if err := h.deps.Registry.Delete(c.Request.Context(), c.Param("id")); err != nil {
		failRegistry(c, err, "Could not delete the mon-client.")
		return
	}
	okMsg(c, "Deleted.", nil)
}
