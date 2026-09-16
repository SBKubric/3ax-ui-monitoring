package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Limits on what the Approve modal may submit. The registry decides the id and
// the token; these only keep nonsense out of it (§9.2).
const (
	maxNameLen   = 128
	maxRegionLen = 64
)

// requestsPayload is the obj of GET /admin/api/requests: everything the
// Requests page draws, including the slim registry the "Approve as
// replacement" picker needs.
type requestsPayload struct {
	ServerTime int64            `json:"serverTime"`
	Pending    int              `json:"pending"`
	RateLimits RateLimits       `json:"rateLimits"`
	Requests   []PendingRequest `json:"requests"`
	Clients    []replaceable    `json:"clients"`
}

// replaceable is one existing mon-client as the replacement picker shows it:
// choosing it takes its name, region and paths (§6, §9.2).
type replaceable struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`
	State  string   `json:"state"`
}

// apiRequests lists the pending registration requests.
func (s *Server) apiRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := s.registry.PendingRequests(r.Context())
	if err != nil {
		s.writeServiceError(w, r, "reading registration requests", err)
		return
	}
	clients, err := s.registry.Clients(r.Context())
	if err != nil {
		s.writeServiceError(w, r, "reading the registry", err)
		return
	}
	payload := requestsPayload{
		ServerTime: s.nowMS(),
		Pending:    len(requests),
		RateLimits: s.limits,
		Requests:   requests,
		Clients:    make([]replaceable, 0, len(clients)),
	}
	if payload.Requests == nil {
		payload.Requests = []PendingRequest{}
	}
	for _, c := range clients {
		payload.Clients = append(payload.Clients, replaceable{
			ID:     c.ID,
			Name:   c.Name,
			Region: c.Region,
			Paths:  pathsOrEmpty(c.Paths),
			State:  c.State,
		})
	}
	writeOK(w, "", payload)
}

// approveRequest is the body of POST /admin/api/requests/{id}/approve, the
// Approve modal of §9.2.
type approveRequest struct {
	// Mode is "new" or "replace".
	Mode        string   `json:"mode"`
	Name        string   `json:"name"`
	Region      string   `json:"region"`
	Paths       []string `json:"paths"`
	MonClientID string   `json:"monClientId"`
}

// Approval modes on the wire.
const (
	modeNew     = "new"
	modeReplace = "replace"
)

// apiApprove approves a request, as a new mon-client or as the replacement of
// an existing one. Everything the form produced is validated here, before the
// registry is asked to issue a token.
func (s *Server) apiApprove(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("id")
	if strings.TrimSpace(requestID) == "" {
		writeFail(w, http.StatusBadRequest, "the request id is missing")
		return
	}
	var body approveRequest
	if !decodeJSON(w, r, &body) {
		return
	}

	approval := Approval{
		RequestID: requestID,
		Name:      strings.TrimSpace(body.Name),
		Region:    strings.TrimSpace(body.Region),
	}
	switch strings.TrimSpace(body.Mode) {
	case modeNew, "":
		approval.Replace = false
	case modeReplace:
		approval.Replace = true
		approval.MonClientID = strings.TrimSpace(body.MonClientID)
		if approval.MonClientID == "" {
			writeFail(w, http.StatusBadRequest, "choose the mon-client this box replaces")
			return
		}
		if !store.ValidMonClientID(approval.MonClientID) {
			writeFail(w, http.StatusBadRequest, "%q is not a mon-client id", approval.MonClientID)
			return
		}
	default:
		writeFail(w, http.StatusBadRequest, "unknown approval mode %q", body.Mode)
		return
	}

	if !approval.Replace {
		// In replacement mode the name, the region and the paths come from
		// the record being replaced (§6), so only a new mon-client must name
		// itself here.
		if approval.Name == "" {
			writeFail(w, http.StatusBadRequest, "the name is required: the mon-client id is derived from it")
			return
		}
	}
	if len(approval.Name) > maxNameLen {
		writeFail(w, http.StatusBadRequest, "the name is longer than %d characters", maxNameLen)
		return
	}
	if len(approval.Region) > maxRegionLen {
		writeFail(w, http.StatusBadRequest, "the region is longer than %d characters", maxRegionLen)
		return
	}
	paths, err := cleanPaths(body.Paths)
	if err != nil {
		writeFail(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	approval.Paths = paths

	client, err := s.registry.Approve(r.Context(), approval)
	if err != nil {
		s.writeServiceError(w, r, "approving the request", err)
		return
	}
	verb := "Approved"
	if approval.Replace {
		verb = "Approved as a replacement of"
	}
	s.log.Info("registration request approved", "requestId", requestID, "monClientId", client.ID, "replacement", approval.Replace)
	writeOK(w, verb+" "+client.ID+". The token is handed to the box once, on its next poll.", client)
}

// apiReject rejects a request (§6: the mon-client waits an hour before trying
// again).
func (s *Server) apiReject(w http.ResponseWriter, r *http.Request) {
	requestID := r.PathValue("id")
	if strings.TrimSpace(requestID) == "" {
		writeFail(w, http.StatusBadRequest, "the request id is missing")
		return
	}
	if err := s.registry.Reject(r.Context(), requestID); err != nil {
		s.writeServiceError(w, r, "rejecting the request", err)
		return
	}
	s.log.Info("registration request rejected", "requestId", requestID)
	writeOK(w, "Request rejected.", nil)
}

// cleanPaths validates the path checkboxes: at least one, each one known, no
// duplicates. It returns them in the canonical order so two equal sets always
// produce the same configuration document (§5).
func cleanPaths(paths []string) ([]string, error) {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if !store.ValidPath(p) {
			return nil, errUnknownPath(p)
		}
		seen[p] = true
	}
	if len(seen) == 0 {
		return nil, errNoPaths
	}
	out := make([]string, 0, len(seen))
	for _, p := range store.DefaultPaths() {
		if seen[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// errNoPaths is an approval or an edit that switched every path off: such a
// mon-client would probe nothing.
var errNoPaths = errors.New("choose at least one path for this mon-client")

// errUnknownPath names a path value that is neither "proxy" nor "direct".
func errUnknownPath(p string) error {
	return fmt.Errorf("unknown path %q: only %q and %q exist", p, store.PathProxy, store.PathDirect)
}

// pathsOrEmpty keeps a nil slice out of the JSON, where it would become null.
func pathsOrEmpty(paths []string) []string {
	if paths == nil {
		return []string{}
	}
	return paths
}
