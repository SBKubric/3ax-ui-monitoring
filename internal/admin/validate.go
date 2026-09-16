package admin

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// numericRange is one settings field and the values it accepts. The bounds are
// deliberately wide: they keep a typo (a probe interval of 6 ms, a downAfter of
// 0 that would make every probe a transition) out of the database without
// second-guessing the operator.
type numericRange struct {
	label string
	value int
	min   int
	max   int
	unit  string
}

// check reports the field being out of range in the words of the Settings page.
func (n numericRange) check() error {
	if n.value < n.min || n.value > n.max {
		return fmt.Errorf("%s must be between %d and %d%s, got %d", n.label, n.min, n.max, n.unit, n.value)
	}
	return nil
}

// validateSettings refuses a Save that would store unusable settings (§9.4).
func validateSettings(v store.Settings) error {
	if v.PanelURL != "" {
		if err := validPanelURL(v.PanelURL); err != nil {
			return err
		}
	}
	if err := validRealHost(v.RealHost); err != nil {
		return err
	}
	ranges := []numericRange{
		{label: "Down after", value: v.DownAfter, min: 1, max: 100},
		{label: "Up after", value: v.UpAfter, min: 1, max: 100},
		{label: "Flapping transitions", value: v.FlapN, min: 2, max: 100},
		{label: "Flapping window", value: v.FlapMin, min: 1, max: 1440, unit: " minutes"},
		{label: "Flapping hold", value: v.FlapHoldMin, min: 1, max: 1440, unit: " minutes"},
		{label: "mon-client offline after", value: v.ClientOfflineAfter, min: 1, max: 100},
		{label: "Panel down after", value: v.PanelDownAfter, min: 1, max: 100},
		{label: "Probe interval", value: v.IntervalMs, min: 5000, max: 3600000, unit: " ms"},
		{label: "Probe budget", value: v.BudgetMs, min: 1000, max: 600000, unit: " ms"},
		{label: "Connect timeout", value: v.ConnectMs, min: 100, max: 120000, unit: " ms"},
		{label: "TLS timeout", value: v.TLSMs, min: 100, max: 120000, unit: " ms"},
		{label: "Headers timeout", value: v.HeadersMs, min: 100, max: 120000, unit: " ms"},
		{label: "Start jitter", value: v.StartJitterMs, min: 0, max: 600000, unit: " ms"},
		{label: "Heartbeat timeout", value: v.HeartbeatTimeoutMs, min: 1000, max: 120000, unit: " ms"},
	}
	for _, r := range ranges {
		if err := r.check(); err != nil {
			return err
		}
	}
	// A probe cycle that cannot finish inside its own interval would overlap
	// itself on every mon-client (§5).
	if v.BudgetMs >= v.IntervalMs {
		return fmt.Errorf("the probe budget (%d ms) must be shorter than the probe interval (%d ms)", v.BudgetMs, v.IntervalMs)
	}
	return nil
}

// validPanelURL checks the base URL of the panel, webBasePath included (§9.4).
func validPanelURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("the panel URL is not a URL: %s", err.Error())
	}
	switch {
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return fmt.Errorf("the panel URL must start with http:// or https://")
	case parsed.Host == "":
		return fmt.Errorf("the panel URL has no host")
	}
	return nil
}

// validRealHost checks the address substituted into "direct" targets: a host,
// optionally with a port, and never a whole URL.
func validRealHost(raw string) error {
	host := strings.TrimSpace(raw)
	if host == "" {
		// Empty means "the host of the panel URL" (§9.4).
		return nil
	}
	if strings.ContainsAny(host, " \t/\\?#") {
		return fmt.Errorf("the address for path direct is a host, optionally with a port, not a URL: %q", raw)
	}
	return nil
}
