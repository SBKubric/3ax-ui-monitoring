package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// probeMaxNonceLen caps the nonce, in bytes of the decoded query value. The
// response repeats the nonce and nothing else from the request, so the cap is
// what stops the endpoint being used as an amplifier.
const probeMaxNonceLen = 128

// ProbeTarget is the parsed target= parameter of GET /v1/probe: the
// "<kind>:<inboundId>:<path>" key of mon-protocol.md §5.2, e.g. "xray:12:proxy"
// or "awg:0:direct".
type ProbeTarget struct {
	// InboundKind is store.InboundKindXray or store.InboundKindAWG.
	InboundKind string
	// InboundID is the panel's inbound id; the single AWG server is 0.
	InboundID int64
	// Path is store.PathProxy or store.PathDirect.
	Path string
}

// String renders the target back in its wire form, for logs.
func (t ProbeTarget) String() string {
	return fmt.Sprintf("%s:%d:%s", t.InboundKind, t.InboundID, t.Path)
}

// ProbeTargets reports whether a target belongs to a mon-client, decided
// against the configuration that mon-client currently has (mon-protocol.md
// §4.2). It is the one lookup GET /v1/probe needs from the rest of
// mon-server, kept narrow so the wiring layer can hand it the
// internal/clientcfg builder; ProbeStore reads the stored document itself
// when it is given nothing.
type ProbeTargets interface {
	HasProbeTarget(ctx context.Context, monClientID string, target ProbeTarget) (bool, error)
}

// ProbeService is everything GET /v1/probe needs: the membership lookup and
// the probe_seen log.
type ProbeService interface {
	ProbeTargets
	// RecordProbeSeen appends one diagnostics row. Its failure never fails
	// the probe.
	RecordProbeSeen(ctx context.Context, seen store.ProbeSeen) error
}

// probeResponse is the body of a successful probe (mon-protocol.md §5.2).
type probeResponse struct {
	Nonce    string `json:"nonce"`
	EgressIP string `json:"egressIp"`
	ServerTS int64  `json:"serverTs"`
}

// RegisterProbeRoutes mounts GET /v1/probe, the tunnel probe of
// mon-server.md §7.5, behind the client token.
//
// The mon-client sends this request *through* a target's tunnel, so the
// source address mon-server sees is the tunnel's egress; the answer reports it
// back as egressIp together with the nonce and mon-server's clock.
//
// The endpoint NEVER changes target state. A probe arriving, or not arriving,
// says nothing that mon-server may act on: its destination is mon-server
// itself, so mon-server's own downtime is indistinguishable from a broken
// tunnel. UP and DOWN are decided solely from the results the mon-client
// reports in its heartbeat (spec §7.2, §7.5). What lands here is a diagnostics
// row in probe_seen and nothing else — no targets row is read for a decision,
// written or touched.
func RegisterProbeRoutes(s *Server, svc ProbeService) {
	s.HandleAuthenticated("GET /v1/probe", func(w http.ResponseWriter, r *http.Request, id Identity) {
		probeHandle(s, svc, w, r, id)
	})
}

// probeHandle answers one tunnel probe.
func probeHandle(s *Server, svc ProbeService, w http.ResponseWriter, r *http.Request, id Identity) {
	q := r.URL.Query()
	target, err := probeParseTarget(q.Get("target"))
	if err != nil {
		// The message describes the expected shape and never repeats the
		// value: the probe answer echoes the nonce, and nothing else from
		// the request is ever written back.
		WriteError(w, http.StatusBadRequest, ErrCodeInvalidBody, err.Error())
		return
	}
	nonce, err := probeNonce(q.Get("n"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, ErrCodeInvalidBody, err.Error())
		return
	}

	// The source address of the connection, never a forwarding header
	// (ClientIP ignores them): egressIp exists to tell the owner which egress
	// the tunnel actually came out of, and a value the caller can set would
	// make the field worthless.
	egressIP := ClientIP(r)
	seenAt := clock.MS(s.Clock().Now())

	known, err := svc.HasProbeTarget(r.Context(), id.MonClientID, target)
	if err != nil {
		// A lookup failure must not fail the probe, and must not claim the
		// target is unknown either: the flag is an assertion about the
		// mon-client's config and needs positive evidence.
		s.Log().Error("probe target lookup", "monClientId", id.MonClientID, "target", target.String(), "error", err)
		known = true
	}

	// A target this mon-client does not have is still answered 200: the
	// endpoint is diagnostics, not validation. The row carries the flag so a
	// mismatch between the served config and what the box probes is visible
	// afterwards (spec §7.5).
	seen := store.ProbeSeen{
		MonClientID:   id.MonClientID,
		InboundKind:   target.InboundKind,
		InboundID:     target.InboundID,
		Path:          target.Path,
		EgressIP:      egressIP,
		SeenAt:        seenAt,
		UnknownTarget: !known,
	}
	if err := svc.RecordProbeSeen(r.Context(), seen); err != nil {
		// Losing the log line is not worth failing the probe over: to the
		// mon-client a failed probe reads as a broken tunnel.
		s.Log().Error("record probe seen", "monClientId", id.MonClientID, "target", target.String(), "error", err)
	}

	WriteJSON(w, http.StatusOK, probeResponse{Nonce: nonce, EgressIP: egressIP, ServerTS: seenAt})
}

// probeNonce validates the n= parameter. It is echoed verbatim, so it is only
// accepted within the cap; missing and empty are the same thing.
func probeNonce(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("query parameter n (nonce) is required")
	}
	if len(raw) > probeMaxNonceLen {
		return "", fmt.Errorf("nonce is longer than %d bytes", probeMaxNonceLen)
	}
	return raw, nil
}

// probeParseTarget parses "<kind>:<inboundId>:<path>" (mon-protocol.md §5.2).
// The inbound id must be in canonical decimal form, so that what lands in
// probe_seen is the same key everything else in mon-server uses; AWG's inbound
// id 0 is a real id, not a missing one.
func probeParseTarget(raw string) (ProbeTarget, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return ProbeTarget{}, errors.New("target must be <kind>:<inboundId>:<path>")
	}
	kind, rawID, path := parts[0], parts[1], parts[2]
	if kind != store.InboundKindXray && kind != store.InboundKindAWG {
		return ProbeTarget{}, fmt.Errorf("target kind must be %q or %q", store.InboundKindXray, store.InboundKindAWG)
	}
	inboundID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || inboundID < 0 || strconv.FormatInt(inboundID, 10) != rawID {
		return ProbeTarget{}, errors.New("target inbound id must be a non-negative decimal number")
	}
	if !store.ValidPath(path) {
		return ProbeTarget{}, fmt.Errorf("target path must be %q or %q", store.PathProxy, store.PathDirect)
	}
	return ProbeTarget{InboundKind: kind, InboundID: inboundID, Path: path}, nil
}

// ProbeStore is the default ProbeService, on top of the SQLite store.
type ProbeStore struct {
	db      *gorm.DB
	targets ProbeTargets
}

// NewProbeStore returns the ProbeService GET /v1/probe runs on. targets
// decides whether a target belongs to a mon-client: pass the
// internal/clientcfg builder once the wiring layer has one, or nil to read the
// mon-client's stored client_configs.document directly, which is what makes
// the endpoint work on its own.
func NewProbeStore(st *store.Store, targets ProbeTargets) *ProbeStore {
	return &ProbeStore{db: st.DB(), targets: targets}
}

// HasProbeTarget implements ProbeTargets.
func (p *ProbeStore) HasProbeTarget(ctx context.Context, monClientID string, target ProbeTarget) (bool, error) {
	if p.targets != nil {
		return p.targets.HasProbeTarget(ctx, monClientID, target)
	}
	var cfg store.ClientConfig
	err := p.db.WithContext(ctx).Where("mon_client_id = ?", monClientID).Take(&cfg).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		// No configuration built yet: the mon-client has no targets at all,
		// so every target is an unknown one.
		return false, nil
	case err != nil:
		return false, fmt.Errorf("api: read client config of %s: %w", monClientID, err)
	}
	return probeDocumentHasTarget(cfg.Document, target)
}

// RecordProbeSeen implements ProbeService.
func (p *ProbeStore) RecordProbeSeen(ctx context.Context, seen store.ProbeSeen) error {
	if err := p.db.WithContext(ctx).Create(&seen).Error; err != nil {
		return fmt.Errorf("api: insert probe_seen: %w", err)
	}
	return nil
}

// probeDocumentHasTarget looks target up in the targets array of a served
// configuration document (mon-protocol.md §4.2).
func probeDocumentHasTarget(document string, target ProbeTarget) (bool, error) {
	var doc probeConfigDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return false, fmt.Errorf("api: decode client config document: %w", err)
	}
	for _, t := range doc.Targets {
		if t.InboundKind == target.InboundKind && t.InboundID == target.InboundID && t.Path == target.Path {
			return true, nil
		}
	}
	return false, nil
}

// probeConfigDocument is the only part of the configuration document
// (mon-protocol.md §4.2) membership is decided on; links, conf blobs and probe
// timings are none of this endpoint's business.
type probeConfigDocument struct {
	Targets []probeConfigTarget `json:"targets"`
}

// probeConfigTarget is one entry of that array.
type probeConfigTarget struct {
	InboundKind string `json:"inboundKind"`
	InboundID   int64  `json:"inboundId"`
	Path        string `json:"path"`
}
