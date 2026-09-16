package admin

import (
	"net/http"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// clientsPayload is the obj of GET /admin/api/clients: the registry table of
// §9.3. It carries no target state — that picture belongs to the panel's
// Monitoring page (§1).
type clientsPayload struct {
	ServerTime int64    `json:"serverTime"`
	Pending    int      `json:"pending"`
	Clients    []Client `json:"clients"`
}

// apiClients returns the registry.
func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.registry.Clients(r.Context())
	if err != nil {
		s.writeServiceError(w, r, "reading the registry", err)
		return
	}
	pending, err := s.registry.PendingCount(r.Context())
	if err != nil {
		s.writeServiceError(w, r, "counting registration requests", err)
		return
	}
	if clients == nil {
		clients = []Client{}
	}
	for i := range clients {
		clients[i].Paths = pathsOrEmpty(clients[i].Paths)
	}
	writeOK(w, "", clientsPayload{ServerTime: s.nowMS(), Pending: pending, Clients: clients})
}

// editClientRequest is the body of POST /admin/api/clients/{id}: the Edit
// modal of §9.3. The id is in the path and never changes.
type editClientRequest struct {
	Name   string   `json:"name"`
	Region string   `json:"region"`
	Paths  []string `json:"paths"`
}

// apiUpdateClient edits name, region and paths.
func (s *Server) apiUpdateClient(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clientID(w, r)
	if !ok {
		return
	}
	var body editClientRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	edit := ClientEdit{
		Name:   strings.TrimSpace(body.Name),
		Region: strings.TrimSpace(body.Region),
	}
	if edit.Name == "" {
		writeFail(w, http.StatusBadRequest, "the name is required")
		return
	}
	if len(edit.Name) > maxNameLen {
		writeFail(w, http.StatusBadRequest, "the name is longer than %d characters", maxNameLen)
		return
	}
	if len(edit.Region) > maxRegionLen {
		writeFail(w, http.StatusBadRequest, "the region is longer than %d characters", maxRegionLen)
		return
	}
	paths, err := cleanPaths(body.Paths)
	if err != nil {
		writeFail(w, http.StatusBadRequest, "%s", err.Error())
		return
	}
	edit.Paths = paths

	if err := s.registry.UpdateClient(r.Context(), id, edit); err != nil {
		s.writeServiceError(w, r, "saving the mon-client", err)
		return
	}
	s.log.Info("mon-client edited", "monClientId", id)
	writeOK(w, "Saved "+id+".", nil)
}

// enabledRequest is the body of POST /admin/api/clients/{id}/enabled.
type enabledRequest struct {
	Enabled *bool `json:"enabled"`
}

// apiSetEnabled flips the Enabled switch. Disabling a mon-client leaves it in
// the registry snapshot and moves its targets to UNKNOWN, which the state
// machine does, not this package (§6).
func (s *Server) apiSetEnabled(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clientID(w, r)
	if !ok {
		return
	}
	var body enabledRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Enabled == nil {
		writeFail(w, http.StatusBadRequest, "enabled is required")
		return
	}
	if err := s.registry.SetClientEnabled(r.Context(), id, *body.Enabled); err != nil {
		s.writeServiceError(w, r, "switching the mon-client", err)
		return
	}
	s.log.Info("mon-client switched", "monClientId", id, "enabled", *body.Enabled)
	if *body.Enabled {
		writeOK(w, id+" enabled.", nil)
		return
	}
	writeOK(w, id+" disabled.", nil)
}

// apiRevoke clears the client token (§6): the box gets 401 on its next call,
// wipes its state and files a fresh registration request, which the
// administrator approves as a replacement to keep the id.
func (s *Server) apiRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clientID(w, r)
	if !ok {
		return
	}
	if err := s.registry.RevokeClient(r.Context(), id); err != nil {
		s.writeServiceError(w, r, "revoking the token", err)
		return
	}
	s.log.Warn("mon-client token revoked", "monClientId", id)
	writeOK(w, "Token of "+id+" revoked. The box will register again; approve that request as a replacement to keep this id.", nil)
}

// apiDelete removes the mon-client and its targets (§6).
func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := s.clientID(w, r)
	if !ok {
		return
	}
	if err := s.registry.DeleteClient(r.Context(), id); err != nil {
		s.writeServiceError(w, r, "deleting the mon-client", err)
		return
	}
	s.log.Warn("mon-client deleted", "monClientId", id)
	writeOK(w, id+" deleted.", nil)
}

// clientID reads and checks the {id} of the path. It answers 400 itself.
func (s *Server) clientID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeFail(w, http.StatusBadRequest, "the mon-client id is missing")
		return "", false
	}
	if !store.ValidMonClientID(id) {
		writeFail(w, http.StatusBadRequest, "%q is not a mon-client id", id)
		return "", false
	}
	return id, true
}
