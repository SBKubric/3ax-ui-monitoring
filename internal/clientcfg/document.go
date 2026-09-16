// Package clientcfg assembles the configuration document mon-server serves to
// each mon-client, and the config revision that tells a mon-client when to
// fetch it again (spec mon-server.md §5, protocol §4.1–§4.3).
//
// The document is deliberately thin. mon-server does not understand a
// subscription link or an AmneziaWG configuration: the panel has already
// rendered both with the address for the path, and this package copies them
// through verbatim (protocol §4.2). What it does own is everything a
// mon-client cannot know by itself — which (inbound, path) pairs it is
// responsible for, how hard to probe them, and where to send the tunnel probe.
//
// The config revision is a hash of the document, so it cannot drift from what
// GET /v1/config serves: the bytes stored in client_configs are the bytes the
// revision was computed over and the bytes the endpoint writes.
package clientcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ProbeEndpointPath is the path of the tunnel probe endpoint a mon-client
// fetches through each target's tunnel (protocol §5.2).
const ProbeEndpointPath = "/v1/probe"

// DefaultProbePort is the port written into the probe url when the bootstrap
// listen address carries none.
const DefaultProbePort = "443"

// Document is the configuration document of protocol §4.2, in the field order
// the specification spells it. It is the whole of what a mon-client is told.
type Document struct {
	// ConfigRevision is the first 16 hex characters of the SHA-256 of this
	// very document with the field removed; see Revision.
	ConfigRevision string `json:"configRevision"`
	MonClientID    string `json:"monClientId"`
	// ProbeURL is where a tunnel probe goes, through the target's tunnel.
	ProbeURL string `json:"probeUrl"`
	Probe    Probe  `json:"probe"`
	// Targets is never null: a mon-client with nothing to probe is told so
	// with an empty array.
	Targets []DocumentTarget `json:"targets"`
}

// Probe is the global probe parameter block of spec §9.4 (Probe tab), the same
// for every mon-client. The state machine thresholds of the same settings page
// are not here: mon-server computes states itself, a mon-client does not need
// them, and they must not move the config revision (protocol §4.2).
type Probe struct {
	IntervalMs         int `json:"intervalMs"`
	BudgetMs           int `json:"budgetMs"`
	ConnectMs          int `json:"connectMs"`
	TLSMs              int `json:"tlsMs"`
	HeadersMs          int `json:"headersMs"`
	StartJitterMs      int `json:"startJitterMs"`
	HeartbeatTimeoutMs int `json:"heartbeatTimeoutMs"`
}

// Target identifies one probed thing inside a mon-client's configuration. It
// is the key the heartbeat results, the state machine, the statistics buckets
// and the tunnel probe all use, minus the mon-client itself.
type Target struct {
	// InboundKind is panel.InboundKindXray or panel.InboundKindAWG.
	InboundKind string `json:"inboundKind"`
	// InboundID is the panel's inbound id; the single AWG server is 0.
	InboundID int64 `json:"inboundId"`
	// Path is panel.PathProxy or panel.PathDirect.
	Path string `json:"path"`
}

// DocumentTarget is one element of the document's targets array: a Target plus
// the material the mon-client dials it with.
//
// Exactly one of Link and Conf is set — a subscription link for an xray
// inbound, an AmneziaWG configuration for the AWG server — and both are the
// panel's own bytes, newlines and all.
type DocumentTarget struct {
	Target
	// Protocol is what the panel reported for the inbound in GET /state
	// ("vless", "awg", …). It is informational: a mon-client decides what to
	// do from the shape of Link or Conf.
	Protocol string `json:"protocol"`
	Link     string `json:"link,omitempty"`
	Conf     string `json:"conf,omitempty"`
}

// marshalDocument renders doc as the bytes stored in client_configs and served
// by GET /v1/config.
//
// HTML escaping is off on purpose. A subscription link separates its query
// parameters with '&', and the default encoder would write every one of them
// as &: still correct JSON, but the stored document would no longer show
// the link the way the panel wrote it.
func marshalDocument(doc Document) ([]byte, error) {
	if doc.Targets == nil {
		doc.Targets = []DocumentTarget{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("clientcfg: marshal document: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ProbeURL renders the tunnel probe endpoint of protocol §4.2 from the
// bootstrap listen address and the public IP mon-clients reach mon-server at.
//
// The port is always written out, exactly as spec §5 spells the url
// ("https://<publicIp>:<port>/v1/probe"), including the 443 an https url could
// leave implicit. One spelling means one config revision: a mon-server moved
// from :8443 to :443 hands out a visibly different url, and an operator
// reading a stored document never has to ask which port it means.
//
// An IPv6 public IP is bracketed, with or without brackets on the way in. The
// result is empty when no public address is configured, which is the one case
// the document cannot be built from.
func ProbeURL(listen, publicIP string) string {
	host := strings.TrimSpace(publicIP)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return ""
	}
	return "https://" + net.JoinHostPort(host, listenPort(listen)) + ProbeEndpointPath
}

// listenPort is the port of a bootstrap listen address such as ":443",
// "0.0.0.0:8443" or "[::]:443". Anything unrecognisable falls back to the
// default port rather than failing: the listener itself has already validated
// the address, and a probe url is better wrong than absent.
func listenPort(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return DefaultProbePort
	}
	if _, port, err := net.SplitHostPort(listen); err == nil && port != "" {
		return port
	}
	if _, err := strconv.Atoi(listen); err == nil {
		return listen
	}
	return DefaultProbePort
}
