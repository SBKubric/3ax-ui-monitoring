package xray

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

const (
	// maxDetail is the protocol's cap on a result's detail (spec §4 step 3,
	// §5: "≤ 256 символов"). Counted in runes, because xray's error chains
	// carry non-ASCII hostnames and a byte cut could split one.
	maxDetail = 256

	// dialMarker is the line xray writes just before it opens the TCP
	// connection of a session (research §2.4): it carries the session id
	// next to the real server's address+port, which is how a probe finds
	// "its" lines when the window has no detour line for its outbound tag
	// (the fallback; see Diagnose).
	dialMarker = "dialing TCP to "

	// detourMarker opens the dispatcher's routing line, `taking detour
	// [<outbound tag>] for [<dest>]`, written under the session id before
	// the transport dials (verified against Xray 26.3.27, loglevel info).
	// The outbound tag is unique per target, so it attributes a session to
	// its target even when several targets share one real server
	// (decision #53 п. 6).
	detourMarker = "taking detour ["

	// realityMarker is the Error line xray writes when the TLS certificate
	// coming back is a real one instead of a Reality-signed one — the target
	// is MITM'd, redirected, or simply not the Reality server any more
	// (research §2.4). It is the only stderr signal that maps to a reason of
	// its own (spec §5: reality_real_cert).
	realityMarker = "REALITY: received real certificate"

	// outboundFailMarker is the Info line that ends a failed outbound: it
	// carries the whole chain of causes (dial timeout, connection refused,
	// invalid Reality connection) and is what we put in detail when there is
	// no dedicated reason (research §2.4, spec §5).
	outboundFailMarker = "failed to process outbound traffic"
)

// ReasonRealityRealCert is the probe reason for a Reality handshake that
// got a real certificate (contract §4.6, spec §5). It is an alias of the
// protocol's own constant rather than a second copy of the string: this
// package names it because Diagnose returns it, and every caller compares
// against the same value proto defines.
const ReasonRealityRealCert = proto.ReasonRealityRealCert

// Target is what Diagnose needs to know about one probe's target to find
// its sessions in the stderr window: the tag of its outbound, unique per
// target in the generated xray.json, and the real server's address and
// port from its link, which several targets may share (decision #53 п. 6).
type Target struct {
	OutboundTag string
	Addr        string
	Port        int
}

// Match is what the stderr window says about one probe: a reason when xray
// named a failure mode we have a dictionary entry for, and always the line
// itself as the human-readable detail (spec §5).
type Match struct {
	// Reason is the probe reason dictionary entry, or "" when the lines only
	// explain the failure without classifying it (a plain failed outbound —
	// the probe keeps whatever reason its own error produced).
	Reason string
	// Detail is the matched line with xray's timestamp/level/session prefix
	// stripped, at most 256 runes (spec §5).
	Detail string
}

// logPrefix matches xray's line prefix: "2026/09/12 15:44:06.887083 [Error]
// [1645185437] ". Diagnose strips it from detail so the heartbeat carries the
// message, not the container's clock, and matches the session id from it.
var logPrefix = regexp.MustCompile(`^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?(?:\[[A-Za-z]+\]\s+)?(?:\[(\d+)\]\s+)?`)

// Diagnose explains a probe to target from the child's stderr window (spec
// §5): it finds the sessions that belong to the target inside the probe's
// [since, until] window and returns the last `REALITY: received real
// certificate` / `failed to process outbound traffic` line of one of them.
//
// A session belongs to the target when xray's dispatcher routed it to the
// target's outbound — `taking detour [<outboundTag>] for [...]`, written
// under the session id before the transport dials. That is what keeps two
// targets on the same real server apart (decision #53 п. 6): their
// `dialing TCP to <addr>:<port>` lines are identical, and matching on them
// alone would hand one target's Reality certificate to both. When the
// window holds no detour line for the tag (an empty tag, a lower loglevel,
// a format change), sessions are found by `dialing TCP to <addr>:<port>`
// as a fallback — minus the sessions a detour line already gave to another
// target.
//
// It is pure by design: the caller (internal/client/probe) hands it a
// Ring.Snapshot and the probe's own start/end times, so the matching is
// testable against the log samples from research §2.4 without a process.
// The bool is false when nothing in the window belongs to this target.
func Diagnose(lines []Line, target Target, since, until time.Time) (Match, bool) {
	sessions := targetSessions(lines, target, since, until)
	if len(sessions) == 0 {
		return Match{}, false
	}

	var (
		found  bool
		reason string
		detail string
	)
	for _, l := range lines {
		if !inWindow(l.At, since, until) {
			continue
		}
		isReality := strings.Contains(l.Text, realityMarker)
		if !isReality && !strings.Contains(l.Text, outboundFailMarker) {
			continue
		}
		if !sessions[sessionID(l.Text)] {
			continue
		}
		found = true
		// The last line of either kind wins as detail (spec §5), while a
		// Reality certificate anywhere in the session fixes the reason: the
		// retry chain that follows it says "invalid connection", which is a
		// consequence, not a second diagnosis.
		detail = trimDetail(stripPrefix(l.Text))
		if isReality {
			reason = ReasonRealityRealCert
		}
	}
	if !found {
		return Match{}, false
	}
	return Match{Reason: reason, Detail: detail}, true
}

// targetSessions is the set of session ids in the window that belong to
// target (see Diagnose for the rule).
func targetSessions(lines []Line, target Target, since, until time.Time) map[string]bool {
	detours := make(map[string]string) // session id → outbound tag
	for _, l := range lines {
		if !inWindow(l.At, since, until) {
			continue
		}
		if tag, ok := detourTag(l.Text); ok {
			if id := sessionID(l.Text); id != "" {
				detours[id] = tag
			}
		}
	}

	sessions := make(map[string]bool)
	if target.OutboundTag != "" {
		for id, tag := range detours {
			if tag == target.OutboundTag {
				sessions[id] = true
			}
		}
		if len(sessions) > 0 {
			return sessions
		}
	}

	for _, l := range lines {
		if !inWindow(l.At, since, until) || !dialsTo(l.Text, target.Addr, target.Port) {
			continue
		}
		id := sessionID(l.Text)
		if id == "" {
			continue
		}
		if tag, routed := detours[id]; routed && tag != target.OutboundTag {
			continue // another target's session on the same real server
		}
		sessions[id] = true
	}
	return sessions
}

// detourTag returns the outbound tag of a dispatcher routing line,
// `app/dispatcher: taking detour [<tag>] for [<dest>]` (verified against
// Xray 26.3.27 at loglevel info).
func detourTag(text string) (string, bool) {
	i := strings.Index(text, detourMarker)
	if i < 0 {
		return "", false
	}
	rest := text[i+len(detourMarker):]
	j := strings.Index(rest, "]")
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// inWindow reports whether t lies in the closed probe window. The bounds are
// inclusive because the first dial happens in the same millisecond the probe
// opens its SOCKS connection (research §2.3).
func inWindow(t, since, until time.Time) bool {
	return !t.Before(since) && !t.After(until)
}

// sessionID returns the `[N]` session id xray prints between the level and
// the module, or "" when the line has none.
func sessionID(text string) string {
	m := logPrefix.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// stripPrefix removes xray's timestamp/level/session prefix from a line.
func stripPrefix(text string) string {
	return strings.TrimSpace(logPrefix.ReplaceAllString(strings.TrimSpace(text), ""))
}

// trimDetail caps a detail at maxDetail runes (spec §5).
func trimDetail(s string) string {
	r := []rune(s)
	if len(r) <= maxDetail {
		return s
	}
	return string(r[:maxDetail])
}

// dialsTo reports whether a `dialing TCP to …` line names this target. xray
// writes the destination as `tcp:<host>:<port>` with the host exactly as the
// outbound has it — a hostname for a domain-fronted target, an IP for a bare
// one — so the comparison is string-wise for hostnames and value-wise for
// IPs (127.0.0.1 and ::ffff:127.0.0.1 are the same host).
func dialsTo(text, addr string, port int) bool {
	i := strings.Index(text, dialMarker)
	if i < 0 {
		return false
	}
	dest := strings.TrimSpace(text[i+len(dialMarker):])
	if j := strings.Index(dest, " "); j >= 0 {
		dest = dest[:j]
	}
	// Xray prefixes the destination with its network ("tcp:"); accept the
	// bare form too so a future log format change does not blind us.
	if rest, ok := strings.CutPrefix(dest, "tcp:"); ok {
		dest = rest
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p != port {
		return false
	}
	return sameHost(host, addr)
}

// sameHost compares two hosts, as IP addresses when both parse as one and
// case-insensitively otherwise (hostnames are case-insensitive in DNS).
func sameHost(a, b string) bool {
	ipA, errA := netip.ParseAddr(strings.Trim(a, "[]"))
	ipB, errB := netip.ParseAddr(strings.Trim(b, "[]"))
	if errA == nil && errB == nil {
		return ipA.Unmap() == ipB.Unmap()
	}
	return strings.EqualFold(a, b)
}
