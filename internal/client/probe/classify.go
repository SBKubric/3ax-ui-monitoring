package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// tlsTimeoutText is the exact sentence net/http produces when
// Transport.TLSHandshakeTimeout fires. It is matched as text because the
// transport wraps it in a plain errors.New with no type of its own, and it is
// the only signal that separates "the tunnel opened and then went silent"
// (tls_timeout) from "the whole probe ran out of budget" (probe_timeout).
const tlsTimeoutText = "TLS handshake timeout"

// Classify maps a failed probe onto the reason dictionary (contract §4.6,
// protocol §5.3, spec §5) and the ≤ 256-rune detail that goes with it.
//
// The order of the checks is the meaning: the most specific evidence wins, so
// an answer we received (a wrong nonce, a non-200) is an http_error even
// though it arrived late, a refused dial is tcp_refused even though it also
// timed out the phase, and probe_timeout is only ever the leftover — the
// whole budget expired and no phase named itself. Phases are consulted for
// the one case the error text cannot express: a dial that completed but took
// longer than the connect budget.
//
// A nil error classifies as ("", "") — a successful probe carries no reason.
func Classify(err error, ph Phases, b Budgets) (reason, detail string) {
	if err == nil {
		return "", ""
	}
	detail = trim(err.Error())
	text := err.Error()

	var nonce *NonceMismatchError
	var status *HTTPStatusError
	switch {
	case errors.As(err, &nonce), errors.As(err, &status):
		// We got an answer through the tunnel and rejected it (spec §5: "не
		// 200 или чужой nonce"). The tunnel itself is fine.
		return proto.ReasonHTTPError, detail

	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(text, "connection refused"):
		// Nothing is listening: the local socks port (xray is down or never
		// started this inbound) or, through the tunnel, the far side.
		return proto.ReasonTCPRefused, detail

	case strings.Contains(text, tlsTimeoutText):
		// Transport.TLSHandshakeTimeout fired: for an xray probe the whole
		// end-to-end phase — Reality handshake, real server → mon-server TCP,
		// TLS 1.3 — did not finish in time (research §6.1).
		return proto.ReasonTLSTimeout, detail

	case connectExceeded(err, ph, b):
		return proto.ReasonTCPTimeout, detail

	case errors.Is(err, context.DeadlineExceeded):
		// The outer context.WithTimeout(b.Budget) fired and no phase claimed
		// the failure first (spec §5: probe_timeout is the overall budget).
		return proto.ReasonProbeTimeout, detail
	}

	// An unnamed transport failure. Before TLS started, the tunnel never
	// carried a byte for us, which is the tcp_refused half of the dictionary
	// (a socks CONNECT the tunnel answered with a failure lands here); after
	// it, the exchange itself broke, which is http_error.
	if ph.TlsMs == nil {
		return proto.ReasonTCPRefused, detail
	}
	return proto.ReasonHTTPError, detail
}

// connectExceeded reports whether the failure belongs to the connect phase:
// net.Dialer.Timeout fired (an i/o timeout on a dial), or the dial did finish
// but only after the connect budget — the case the error text alone cannot
// show, because the transport reports whatever happened *after* the slow dial.
func connectExceeded(err error, ph Phases, b Budgets) bool {
	if b.Connect > 0 && ph.ConnectMs != nil && *ph.ConnectMs >= b.Connect.Milliseconds() {
		return true
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	// A dial timeout that never reached ConnectDone leaves no TLS phase and
	// no connect measurement: it is still the connect phase that expired.
	return ph.ConnectMs == nil && ph.TlsMs == nil
}
