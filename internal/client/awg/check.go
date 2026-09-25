package awg

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
)

// checkEndpoint stands in for a host-name Endpoint during Check. It is
// TEST-NET-1 (RFC 5737): nothing is ever sent to it, because the device
// Check builds is never brought up.
var checkEndpoint = netip.MustParseAddr("192.0.2.1")

// Check is the trial IpcSet a revision's AWG-target has to pass to be
// applied (decision #53 п. 2): a netstack device is built for cfg exactly
// as Open builds it, handed the UAPI blob and closed again — without Up, so
// no UDP socket is bound and no packet leaves the box. internal/client/config
// passes most values through verbatim (Jc, S1, H1, …), and amneziawg-go is
// the only judge of them; asking it here makes a value it refuses a
// rejected target of this revision (the error names the key) rather than
// an awg_no_handshake on every probe.
//
// A host name in Endpoint is swapped for a placeholder address first: the
// device accepts only IPs, and the probe resolves the name before every
// IpcSet (decision #53 п. 1), so a name is not a reason to reject.
func Check(cfg *config.AWGConfig) error {
	if cfg == nil {
		return fmt.Errorf("awg: no config")
	}
	uapi, err := resolveEndpoints(context.Background(), placeholderResolver{}, cfg.UAPI)
	if err != nil {
		return err
	}
	tun, err := newNetTUN(cfg.LocalAddresses, cfg.MTU)
	if err != nil {
		return fmt.Errorf("awg: create netstack tun: %w", err)
	}
	// A logger that drops everything: IpcSet logs its own error before
	// returning it, and the returned one is all a rejection needs.
	dev := newDevice(tun, device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("awg: apply uapi config: %w", err)
	}
	return nil
}

// placeholderResolver answers every name with checkEndpoint.
type placeholderResolver struct{}

func (placeholderResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{checkEndpoint}, nil
}
