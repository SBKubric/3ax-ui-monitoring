package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clientcfg"
)

// ErrCodeConfigUnavailable is returned by GET /v1/config while mon-server has
// not assembled a configuration for this mon-client yet.
const ErrCodeConfigUnavailable = "config_unavailable"

// configRetryAfter is the Retry-After sent with that answer, in seconds. The
// panel poll runs once a minute and builds the missing configuration on its
// next pass, so a mon-client that asks again shortly gets a real answer
// without waiting for its own probe cycle.
const configRetryAfter = "10"

// ConfigService is the part of internal/clientcfg this endpoint needs: the
// stored document and its revision, as they are in client_configs.
type ConfigService interface {
	Document(ctx context.Context, monClientID string) (json.RawMessage, string, error)
}

// RegisterConfigRoutes mounts GET /v1/config (protocol §4.2) behind the client
// token.
//
// The answer is the document mon-server stored for the caller, byte for byte,
// because the configRevision inside it is a hash of those very bytes: anything
// that re-encoded the document on the way out could hand a mon-client a
// revision its own document does not hash to.
func RegisterConfigRoutes(s *Server, svc ConfigService) {
	s.HandleAuthenticated("GET /v1/config", func(w http.ResponseWriter, r *http.Request, id Identity) {
		document, revision, err := svc.Document(r.Context(), id.MonClientID)
		switch {
		case errors.Is(err, clientcfg.ErrNoConfig):
			configWriteNotBuilt(w)
			return
		case err != nil:
			s.Log().Error("read mon-client config", "monClientId", id.MonClientID, "error", err)
			WriteError(w, http.StatusInternalServerError, ErrCodeInternal, "could not read the configuration")
			return
		}
		if len(bytes.TrimSpace(document)) == 0 {
			// A row with an empty document is a bug upstream, not a mon-client
			// error; answer it the same way as no row at all rather than send
			// an empty body a mon-client would have to parse.
			s.Log().Error("stored mon-client config is empty", "monClientId", id.MonClientID, "revision", revision)
			configWriteNotBuilt(w)
			return
		}
		s.Log().Debug("served mon-client config", "monClientId", id.MonClientID, "revision", revision)
		configWriteDocument(w, document)
	})
}

// configWriteNotBuilt answers a mon-client whose configuration does not exist
// yet.
//
// It is a 503 and not an empty document on purpose. mon-server has nothing to
// say until its first successful panel poll, and an empty document is not
// "nothing to say" — it is the instruction to probe nothing, with a revision
// of its own that the mon-client would apply and report in every heartbeat.
// Worse, that document would have to be invented in the handler, while
// everything served here otherwise comes out of client_configs, where the
// revision and the bytes are guaranteed to agree. A 503 with Retry-After says
// what is actually true: come back shortly, this is temporary.
func configWriteNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Retry-After", configRetryAfter)
	WriteError(w, http.StatusServiceUnavailable, ErrCodeConfigUnavailable,
		"no configuration has been assembled for this mon-client yet")
}

// configWriteDocument writes a stored document as the response body exactly as
// client_configs holds it.
//
// It deliberately does not go through WriteJSON: handing a json.RawMessage to
// an encoder compacts it, escapes the '&' between a subscription link's query
// parameters and appends a newline, so the body would no longer be the bytes
// the config revision was computed over.
func configWriteDocument(w http.ResponseWriter, document json.RawMessage) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(document)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}
