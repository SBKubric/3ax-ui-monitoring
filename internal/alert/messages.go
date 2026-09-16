package alert

import (
	"fmt"
	"strings"
)

// The message catalog of mon-server.md §8: the only things mon-server tells the
// owner itself. Everything else reaches Telegram through the panel. The
// catalog lives here rather than in internal/tg so that the panel client and
// the state machine can phrase an alert without importing a Telegram client.

// viaMonServer marks a transition the panel would normally have announced, sent
// by mon-server because the panel is unreachable (§4.1).
const viaMonServer = " — via mon-server"

// MsgPanelUnreachable announces entering PANEL_DOWN. reason is the contract
// reason code that tripped it, such as http_timeout or conn_refused.
func MsgPanelUnreachable(reason string) string {
	return fmt.Sprintf("mon-server: panel unreachable (%s)", reason)
}

// MsgPanelBack announces leaving PANEL_DOWN and how many buffered events were
// resent to the panel.
func MsgPanelBack(resent int) string {
	return fmt.Sprintf("mon-server: panel back, %d events resent", resent)
}

// MsgPanelRejectsToken reports a bare 404 from GET /state, which per the panel
// contract §2 means a wrong token, a wrong path, or monitoring switched off.
func MsgPanelRejectsToken() string {
	return "mon-server: panel rejects monitoring token or monitoring is disabled"
}

// MsgConfigError reports that a mon-client could not apply its config. detail
// is trimmed to its first line, as the spec shows only that.
func MsgConfigError(monClientID, detail string) string {
	return fmt.Sprintf("mon-client %s: config error %s", monClientID, FirstLine(detail))
}

// MsgTargetTransition phrases a target transition sent while the panel is down.
// target is the "kind:inboundId:path" key.
func MsgTargetTransition(monClientID, target, from, to, reason string) string {
	msg := fmt.Sprintf("target %s on %s: %s → %s", target, monClientID, from, to)
	if reason != "" {
		msg += " (" + reason + ")"
	}
	return msg + viaMonServer
}

// MsgMonClientTransition phrases a mon-client transition sent while the panel
// is down. It keeps the panel's wording, "name (region) STATE".
func MsgMonClientTransition(name, region, to string) string {
	return fmt.Sprintf("mon-client %s (%s) %s%s", name, region, to, viaMonServer)
}

// FirstLine returns the first non-empty line of s, trimmed, capped at 256
// characters — the same cap the protocol puts on a probe detail.
func FirstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 256 {
			return line[:256]
		}
		return line
	}
	return ""
}
