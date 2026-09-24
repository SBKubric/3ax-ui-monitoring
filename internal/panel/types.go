// Package panel is mon-server's whole relationship with the real server's
// panel: the typed client for the contract under <webBasePath>mon/v1
// (docs/spec/monitoring-contract.md in the panel repo), the once-a-minute
// poll cycle (spec §4), the outbox flush and the PANEL_DOWN mode (spec
// §4.1). Nothing else in mon-server speaks HTTP to the panel — a package
// that needs panel material asks the Poller for it, and a package that
// needs the panel told about something enqueues an event in the outbox.
//
// The types below mirror the panel's own service types field-for-field,
// including their JSON tags and their Go spellings (InboundId, SubId), so
// that a change on either side shows up as a mismatch a reader can see
// rather than a silent rename. They deliberately do NOT carry validation
// tags: the contract (§1) requires mon-server to tolerate fields it does
// not know, so every response is decoded leniently and anything unexpected
// is ignored, never rejected.
package panel

// RequiredContract is the lowest monitoring contract version mon-server can
// work with (decision #80 п. 9). Contract 2 is the per-peer probe set: an
// AWG probe peer per mon-client × path, handed out by GET /probe/configs as
// one item per mon-client carrying its monClientId. A contract-1 panel
// hands out one shared AWG peer that the paths and mon-clients steal from
// each other, so mon-server refuses to build targets from it rather than
// monitor with a probe that is guaranteed to fail on one side.
const RequiredContract = 2

// Inbound is one sanitised inbound from GET /state (contract §4.1): the
// panel never sends settings, stream settings or keys here, only what
// mon-server needs to name a target and show it to an operator. An AWG
// server arrives as Kind "awg" with InboundId 0, which is why InboundId is
// a plain int with no "absent" value — every inbound has one.
type Inbound struct {
	Kind      string `json:"kind"`
	InboundId int    `json:"inboundId"`
	Tag       string `json:"tag"`
	Remark    string `json:"remark"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Enable    bool   `json:"enable"`
}

// InboundRef names an inbound without describing it — the form POST
// /probe/ensure answers with in its "created" list (contract §4.3).
type InboundRef struct {
	Kind      string `json:"kind"`
	InboundId int    `json:"inboundId"`
}

// Override is the panel's host override (CONTEXT.md: the global setting that
// swaps the real server's address for the proxy front's in every config the
// panel hands out). Host is an empty string while Enabled is false, and the
// pair decides whether mon-server has a "proxy" path to probe at all
// (spec §4 step 3).
type Override struct {
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
}

// Probe is the state of the panel's probe account set (contract §4.1).
// SubId is a pointer because it is null until the first POST /probe/ensure
// creates the set — "not created yet" and "created with an empty id" are
// different things, and only the first is legal.
type Probe struct {
	SubId       *string `json:"subId"`
	LastEnsured int64   `json:"lastEnsured"`
}

// State is the GET /state body (contract §4.1): the panel's whole
// configuration as far as monitoring is concerned, plus the Revision that
// tells mon-server whether anything it cares about has changed since the
// last poll.
type State struct {
	Contract     int       `json:"contract"`
	PanelVersion string    `json:"panelVersion"`
	ServerTime   int64     `json:"serverTime"`
	Revision     string    `json:"revision"`
	Override     Override  `json:"override"`
	Probe        Probe     `json:"probe"`
	Inbounds     []Inbound `json:"inbounds"`
	Stale        struct {
		ThresholdMinutes int `json:"thresholdMinutes"`
	} `json:"stale"`
}

// MonClientSnapshot is one mon-client as the panel caches it for its own UI
// (contract §4.3, the panel's MonClient). The panel treats State as opaque:
// it never recomputes it, so this is purely mon-server reporting what it
// believes, and a full snapshot replaces the panel's cache on every ensure.
type MonClientSnapshot struct {
	Id            string `json:"id"`
	Name          string `json:"name"`
	Region        string `json:"region"`
	State         string `json:"state"`
	LastHeartbeat int64  `json:"lastHeartbeat"`
}

// EnsureResult is the POST /probe/ensure body (contract §4.3). Created is
// normally empty — ensure is idempotent and only does work the first time
// an inbound appears — and Present is the size of the probe set afterwards,
// which an operator can compare against the inbound count.
//
// Unallocated (contract 2, decision #80 п. 10) lists the mon-clients the
// panel could not give an AWG probe peer because its address pool is
// exhausted. The ensure still succeeds; those mon-clients simply get no AWG
// item from GET /probe/configs, and their AWG targets go PAUSED
// no_probe_link. The field may be absent, which means none.
type EnsureResult struct {
	SubId       string       `json:"subId"`
	Revision    string       `json:"revision"`
	LastEnsured int64        `json:"lastEnsured"`
	Created     []InboundRef `json:"created"`
	Present     int          `json:"present"`
	Unallocated []string     `json:"unallocated,omitempty"`
}

// ProbeItem is the material for one inbound on one path (contract §4.4):
// either an xray subscription Link or an AWG Filename plus Conf. mon-server
// passes whichever it got through to the mon-client verbatim (spec §5) —
// the panel has already applied the host override or the direct host, so
// rewriting anything here would only introduce a way to get it wrong.
//
// MonClientId is set on AWG items only (contract 2, decision #80 п. 7): the
// panel keeps one AWG probe peer per mon-client × path, so one path's
// answer carries one AWG item per mon-client, and each one belongs to the
// mon-client it names. xray items leave it empty: an xray probe account is
// shared by every mon-client.
type ProbeItem struct {
	Kind        string `json:"kind"`
	InboundId   int    `json:"inboundId"`
	MonClientId string `json:"monClientId,omitempty"`
	Link        string `json:"link,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Conf        string `json:"conf,omitempty"`
}

// ProbeConfigs is the GET /probe/configs body (contract §4.4). Revision is
// what makes the answer safe to use: the panel may have changed between the
// GET /state that reported a revision and this call, and an answer carrying
// a different revision is discarded rather than mixed with the state it does
// not belong to (spec §4 step 3).
type ProbeConfigs struct {
	Revision string      `json:"revision"`
	Path     string      `json:"path"`
	Items    []ProbeItem `json:"items"`
}

// StatPayload is one 5-minute aggregate for POST /stats (contract §4.7, the
// panel's MonStatIn). Every latency field is a pointer because the contract
// spells "no measurement" as JSON null, which a plain int64 would flatten
// into a very believable zero.
type StatPayload struct {
	MonClientId  string `json:"monClientId"`
	InboundKind  string `json:"inboundKind"`
	InboundId    int    `json:"inboundId"`
	Path         string `json:"path"`
	BucketStart  int64  `json:"bucketStart"`
	NOk          int    `json:"nOk"`
	NFail        int    `json:"nFail"`
	LatencyMinMs *int64 `json:"latencyMinMs"`
	LatencyAvgMs *int64 `json:"latencyAvgMs"`
	LatencyMaxMs *int64 `json:"latencyMaxMs"`
	HandshakeMs  *int64 `json:"handshakeMs"`
}

// Ignored is one record the panel accepted the batch but did not apply
// (contract §3: an event or stat for an inbound the panel has since
// deleted). It is reported, not retried — the panel holds nothing for an
// unknown inbound, so resending would only produce the same answer.
type Ignored struct {
	Id    string `json:"id,omitempty"`
	Key   string `json:"key,omitempty"`
	Error string `json:"error"`
}

// Rejected is one batch element the panel refused on its own (decision
// #50, contract §4.6/§4.7): the element failed validation, its neighbours
// in the batch did not, and the panel answered 200 for the rest. Index is
// the element's position in the batch as sent; Id is the event id and is
// only present on POST /events. A rejected element would be refused the
// same way on every resend, so the sender drops it rather than retrying.
type Rejected struct {
	Index int    `json:"index"`
	Id    string `json:"id,omitempty"`
	Error string `json:"error"`
}

// EventsResult is the POST /events body (contract §4.6). Duplicates is not
// an error: the outbox may legitimately resend a batch whose confirmation
// was lost, and the panel deduplicates by event id. Rejected lists the
// elements the panel refused; everything else in the batch is accepted.
//
// A panel from before per-element answers replies with a bare 200 and no
// body, which the client decodes as the zero value — nothing rejected, so
// the whole batch counts as accepted (decision #50).
type EventsResult struct {
	Accepted   int        `json:"accepted"`
	Duplicates int        `json:"duplicates"`
	Ignored    []Ignored  `json:"ignored"`
	Rejected   []Rejected `json:"rejected"`
}

// StatsResult is the POST /stats body (contract §4.7). There is no
// Duplicates counter because stats are upserted by key, so a resend
// overwrites rather than collides. Rejected and the empty-body rule are the
// same as EventsResult's.
type StatsResult struct {
	Accepted int        `json:"accepted"`
	Ignored  []Ignored  `json:"ignored"`
	Rejected []Rejected `json:"rejected"`
}
