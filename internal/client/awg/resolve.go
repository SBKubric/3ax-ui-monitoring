package awg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Resolver looks a host name up. *net.Resolver satisfies it; tests hand
// the Prober a table instead, so no probe test depends on real DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// resolveEndpoints rewrites every `endpoint=<host>:<port>` line of a UAPI
// blob whose host is a name into `endpoint=<ip>:<port>` (decision #53 п. 1).
//
// amneziawg-go takes nothing but an IP there: its bind parses the value
// with netip.ParseAddrPort and never looks a name up, so a `.conf` with
// `Endpoint = awg.example.com:51820` fails IpcSet with "unable to parse IP"
// on every probe (research #60). wg-quick and awg-quick resolve once, when
// they read the `.conf`; a probe resolves every time instead, because the
// device is rebuilt for every probe anyway (spec §5) and a name whose IP
// moved is then followed within one cycle.
//
// An endpoint that already is an IP is left byte for byte as it was and is
// never looked up. When a name has addresses of both families the first
// IPv4 one wins: a mon-client box is far more likely to lack an IPv6 route
// than an IPv4 one, and a probe dialling an unroutable family would report
// a tunnel failure that is the box's own. A failed lookup is returned as
// "endpoint: resolve <host>: <cause>", which is the detail of the
// awg_no_handshake the probe then reports.
func resolveEndpoints(ctx context.Context, r Resolver, uapi string) (string, error) {
	lines := strings.Split(uapi, "\n")
	for i, line := range lines {
		value, ok := strings.CutPrefix(line, "endpoint=")
		if !ok {
			continue
		}
		if _, err := netip.ParseAddrPort(value); err == nil {
			continue
		}
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return "", fmt.Errorf("endpoint: %q: %w", value, err)
		}
		addr, err := lookup(ctx, r, host)
		if err != nil {
			return "", fmt.Errorf("endpoint: resolve %s: %w", host, err)
		}
		lines[i] = "endpoint=" + net.JoinHostPort(addr.String(), port)
	}
	return strings.Join(lines, "\n"), nil
}

// lookup is one name's address as resolveEndpoints picks it: the first
// IPv4 answer, else the first answer, 4-in-6 forms unmapped.
func lookup(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses")
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0].Unmap(), nil
}
