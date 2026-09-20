package admin

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Registration rate limits, shown in the Requests page header exactly as the
// prototype does ("1/min per IP · ≤ 3 pending per IP · ≤ 20 global"). They
// are spec §6's numbers, repeated here only for display — internal/registry
// is the one place that enforces them.
const (
	limitPerIPPerMin  = 1
	limitPendingPerIP = 3
	limitPendingTotal = 20
)

// requestView is one pending registration request as the Requests page shows
// it (spec §9.2): the box's own claims (hostname, version, public IP), the
// pairing code to compare against the box's log, the countdown, and the
// replacement hint.
type requestView struct {
	RequestId   string `json:"requestId"`
	PairingCode string `json:"pairingCode"`
	Hostname    string `json:"hostname"`
	Version     string `json:"version"`
	PublicIp    string `json:"publicIp"`
	RemoteIp    string `json:"remoteIp"`
	CreatedAt   int64  `json:"createdAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	// Attempt is how many times this box has asked to join (spec §9.2:
	// "номер попытки"), counted over every request that ever carried this
	// hostname.
	Attempt int `json:"attempt"`
	// SuggestReplacement is spec §6's hint — non-nil when this request's
	// hostname or public IP matches a mon-client already in the registry,
	// which the page highlights as "same hostname as msk-1: replacement?".
	// The administrator still chooses the mode explicitly.
	SuggestReplacement *suggestView `json:"suggestReplacement"`
}

// suggestView names the mon-client a request could replace, with enough of
// its record for the Approve modal to pre-fill the replacement mode.
type suggestView struct {
	MonClientId string   `json:"monClientId"`
	Name        string   `json:"name"`
	Region      string   `json:"region"`
	Paths       []string `json:"paths"`
	// Reason is "hostname" or "ip": which of spec §6's two matches fired,
	// so the page can say which one it means.
	Reason string `json:"reason"`
}

// listRequests answers the Requests page: the pending requests, the existing
// mon-clients (the "Replace an existing one" picker's options), the rate
// limits for the header, and the server's own clock so the expiry countdown
// ticks against mon-server's time rather than the browser's.
func (h *Handler) listRequests(c *gin.Context) {
	ctx := c.Request.Context()

	reqs, err := h.deps.Registry.PendingRequests(ctx)
	if err != nil {
		slog.Error("admin: listing pending registration requests failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not list registration requests.")
		return
	}

	views := make([]requestView, 0, len(reqs))
	for i := range reqs {
		req := &reqs[i]
		v := requestView{
			RequestId:   req.RequestId,
			PairingCode: req.PairingCode,
			Hostname:    req.Hostname,
			Version:     req.Version,
			PublicIp:    req.PublicIp,
			RemoteIp:    req.RemoteIp,
			CreatedAt:   req.CreatedAt,
			ExpiresAt:   req.ExpiresAt,
			Attempt:     h.attemptNumber(req),
		}
		if mc, okSuggest := h.deps.Registry.SuggestReplacement(ctx, req); okSuggest {
			reason := "hostname"
			if req.PublicIp != "" && mc.RemoteIp == req.PublicIp {
				reason = "ip"
			}
			v.SuggestReplacement = &suggestView{
				MonClientId: mc.Id,
				Name:        mc.Name,
				Region:      mc.Region,
				Paths:       pathsOrDefault(mc),
				Reason:      reason,
			}
		}
		views = append(views, v)
	}

	clients, err := h.deps.Registry.List(ctx)
	if err != nil {
		slog.Error("admin: listing mon-clients for the replacement picker failed", "err", err)
		fail(c, http.StatusInternalServerError, "Could not list mon-clients.")
		return
	}
	picker := make([]suggestView, 0, len(clients))
	for i := range clients {
		picker = append(picker, suggestView{
			MonClientId: clients[i].Id,
			Name:        clients[i].Name,
			Region:      clients[i].Region,
			Paths:       pathsOrDefault(&clients[i]),
		})
	}

	ok(c, gin.H{
		"pending": views,
		"clients": picker,
		"now":     clock.Ms(h.deps.Clock.Now()),
		"limits": gin.H{
			"perIpPerMin":   limitPerIPPerMin,
			"pendingPerIp":  limitPendingPerIP,
			"pendingGlobal": limitPendingTotal,
		},
	})
}

// attemptNumber counts how many requests this hostname has ever produced,
// including this one (spec §9.2 shows it next to the version). A box that
// keeps retrying is worth spotting: it usually means its earlier requests
// expired unapproved. A hostname the box did not send counts as one attempt
// rather than joining every other anonymous request into one big number.
func (h *Handler) attemptNumber(req *store.RegistrationRequest) int {
	if req.Hostname == "" {
		return 1
	}
	var n int64
	if err := h.deps.Store.DB.Model(&store.RegistrationRequest{}).
		Where("hostname = ? AND created_at <= ?", req.Hostname, req.CreatedAt).
		Count(&n).Error; err != nil {
		slog.Error("admin: counting registration attempts failed", "err", err)
		return 1
	}
	return int(n)
}

// pathsOrDefault is a mon-client's paths with spec §6's default applied, so
// the UI never has to decide what an empty list means.
func pathsOrDefault(mc *store.MonClient) []string {
	paths := mc.PathsList()
	if len(paths) == 0 {
		return []string{store.PathProxy, store.PathDirect}
	}
	return paths
}

// approveBody is the Approve modal's submission (spec §9.2). Mode is "new"
// or "replace" — the administrator's explicit choice, never inferred from
// the hint — and the remaining fields are only read in the mode they belong
// to: a replacement keeps the existing record's name, region and paths
// (spec §6).
type approveBody struct {
	Mode       string   `json:"mode"`
	Name       string   `json:"name"`
	Region     string   `json:"region"`
	Paths      []string `json:"paths"`
	ExistingId string   `json:"existingId"`
}

// Approval modes, the two halves of spec §9.2's "New mon-client / Replace an
// existing one" switch.
const (
	modeNew     = "new"
	modeReplace = "replace"
)

// approveRequest turns a pending request into a mon-client, in whichever of
// the two modes the administrator chose (spec §6, §9.2). Both paths mint a
// fresh token that the box collects exactly once on its next poll; the
// replacement path keeps the existing id, history, name, region and paths
// and revokes the old token.
func (h *Handler) approveRequest(c *gin.Context) {
	var body approveBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, "Malformed approval.")
		return
	}
	id := c.Param("id")

	var (
		mc  *store.MonClient
		err error
	)
	switch body.Mode {
	case modeReplace:
		if body.ExistingId == "" {
			fail(c, http.StatusBadRequest, "Choose the mon-client this request replaces.")
			return
		}
		mc, err = h.deps.Registry.ApproveAsReplacement(c.Request.Context(), id, body.ExistingId)
	case modeNew, "":
		if body.Name == "" {
			fail(c, http.StatusBadRequest, "Name is required.")
			return
		}
		mc, err = h.deps.Registry.Approve(c.Request.Context(), id, registry.ApproveInput{
			Name:   body.Name,
			Region: body.Region,
			Paths:  body.Paths,
		})
	default:
		fail(c, http.StatusBadRequest, "Unknown approval mode "+body.Mode+".")
		return
	}
	if err != nil {
		failRegistry(c, err, "Could not approve the request.")
		return
	}

	msg := "Approved. The token is handed to " + mc.Id + " on its next poll."
	if body.Mode == modeReplace {
		msg = "Approved as a replacement. " + mc.Id + " keeps its id and history; the old token is revoked."
	}
	okMsg(c, msg, gin.H{"monClientId": mc.Id})
}

// rejectRequest records the administrator's refusal (spec §6: the box waits
// an hour and tries again with a new pairing code — that wait lives on the
// mon-client side, mon-server only records the decision).
func (h *Handler) rejectRequest(c *gin.Context) {
	if err := h.deps.Registry.Reject(c.Request.Context(), c.Param("id")); err != nil {
		failRegistry(c, err, "Could not reject the request.")
		return
	}
	okMsg(c, "Rejected.", nil)
}

// failRegistry maps internal/registry's sentinel errors onto the statuses
// the admin UI needs to distinguish: gone (someone else acted first, or the
// five minutes ran out), bad input, or a genuine server fault. fallback is
// the message for the last case, where the administrator can do nothing but
// look at the log.
func failRegistry(c *gin.Context, err error, fallback string) {
	switch {
	case errors.Is(err, registry.ErrRequestNotFound):
		fail(c, http.StatusNotFound, "That registration request is gone — it may have expired or already been handled.")
	case errors.Is(err, registry.ErrRequestExpired):
		fail(c, http.StatusConflict, "That request expired. The box will send a new one with a new pairing code.")
	case errors.Is(err, registry.ErrRequestNotPending):
		fail(c, http.StatusConflict, "That request has already been decided.")
	case errors.Is(err, registry.ErrClientNotFound):
		fail(c, http.StatusNotFound, "No such mon-client.")
	case errors.Is(err, registry.ErrInvalidPath):
		fail(c, http.StatusBadRequest, "Paths must be \"proxy\", \"direct\", or both.")
	default:
		slog.Error("admin: registry call failed", "err", err)
		fail(c, http.StatusInternalServerError, fallback)
	}
}
