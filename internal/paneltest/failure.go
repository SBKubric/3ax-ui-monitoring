package paneltest

import (
	"net/http"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
)

// Endpoints a failure can be pinned to. They are the contract's paths under
// /mon/v1/, with Any standing for all of them.
const (
	Any          = "*"
	State        = "state"
	ProbeEnsure  = "probe/ensure"
	ProbeConfigs = "probe/configs"
	Probe        = "probe"
	Events       = "events"
	Stats        = "stats"
)

// Failure is the answer the stub gives in place of the real one, so that a
// test can drive the client's error and retry policy. The zero Failure is not
// useful; build one with the constructors below.
type Failure struct {
	// Status is the HTTP status to answer with.
	Status int
	// Code and Message fill the panel's error envelope (contract §3). An
	// empty Code sends no body at all, which is what a bare 404 looks like.
	Code    string
	Message string
	// Body replaces the envelope with a raw string, for malformed answers.
	Body string
	// Hang answers nothing and holds the request open until the client gives
	// up or the stub is closed, which is how a timeout is provoked without
	// any test sleeping.
	Hang bool
	// Times is how many calls the failure applies to. Zero means every call
	// until it is cleared.
	Times int
}

// NotFound is the bare 404 the panel gives for a missing or wrong token, a
// wrong path, or monitoring switched off (contract §2).
func NotFound() Failure { return Failure{Status: http.StatusNotFound} }

// ServerError is a plain 500, the retryable panel failure.
func ServerError() Failure {
	return Failure{Status: http.StatusInternalServerError, Code: "internal", Message: "panel is broken"}
}

// Starting is the 503 a panel gives while it is coming up or its database is
// away. Unlike XrayUnavailable it is retryable.
func Starting() Failure {
	return Failure{Status: http.StatusServiceUnavailable, Code: "starting", Message: "panel is starting"}
}

// Hanging never answers: the request stays open until the client's timeout or
// the caller's context ends it.
func Hanging() Failure { return Failure{Hang: true} }

// InvalidBody is the 400 a malformed batch gets.
func InvalidBody(message string) Failure {
	return Failure{Status: http.StatusBadRequest, Code: panel.CodeInvalidBody, Message: message}
}

// OverrideDisabled is the 409 of GET /probe/configs without a host while the
// panel's host override is off (contract §4.4).
func OverrideDisabled() Failure {
	return Failure{
		Status:  http.StatusConflict,
		Code:    panel.CodeOverrideDisabled,
		Message: "host override is disabled",
	}
}

// ProbeNotEnsured is the 409 of GET /probe/configs before the probe set has
// been created.
func ProbeNotEnsured() Failure {
	return Failure{
		Status:  http.StatusConflict,
		Code:    panel.CodeProbeNotEnsured,
		Message: "probe set is not ensured",
	}
}

// XrayUnavailable is the 503 of POST /probe/ensure when the panel could not
// reach xray: the probe set is partly created and the next ensure finishes it.
func XrayUnavailable() Failure {
	return Failure{
		Status:  http.StatusServiceUnavailable,
		Code:    panel.CodeXrayUnavailable,
		Message: "xray api is unavailable",
	}
}

// BatchTooLarge is the 413 of a batch over the limits of contract §3.
func BatchTooLarge() Failure {
	return Failure{
		Status:  http.StatusRequestEntityTooLarge,
		Code:    panel.CodeBatchTooLarge,
		Message: "batch is too large",
	}
}

// Once limits the failure to the next call.
func (f Failure) Once() Failure { return f.NTimes(1) }

// NTimes limits the failure to the next n calls.
func (f Failure) NTimes(n int) Failure {
	f.Times = n
	return f
}
