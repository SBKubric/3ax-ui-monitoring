package awg

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// fakeResolver answers host lookups from a table and records every name it
// was asked for, so a test can prove an IP endpoint is never looked up.
type fakeResolver struct {
	addrs map[string][]netip.Addr
	err   error

	mu    sync.Mutex
	asked []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	addrs, ok := r.addrs[host]
	if !ok {
		return nil, errors.New("lookup " + host + ": no such host")
	}
	return addrs, nil
}

func (r *fakeResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asked...)
}

// TestResolveEndpoints pins decision #53 п. 1 at the UAPI level: every
// peer's `endpoint=` that names a host is rewritten to an IP (amneziawg-go
// accepts nothing else, research #60), an IP endpoint is left exactly as
// it is and never looked up, and a lookup that fails names the host.
func TestResolveEndpoints(t *testing.T) {
	const head = "private_key=01\npublic_key=02\n"
	table := map[string][]netip.Addr{
		"awg.example":  {netip.MustParseAddr("198.51.100.50")},
		"dual.example": {netip.MustParseAddr("2001:db8::5"), netip.MustParseAddr("198.51.100.51")},
		"v6.example":   {netip.MustParseAddr("2001:db8::6")},
		"mapped.test":  {netip.MustParseAddr("::ffff:198.51.100.52")},
	}

	cases := []struct {
		name      string
		uapi      string
		want      string
		wantAsked []string
		wantErr   string
	}{
		{
			name: "IPv4 endpoint stays as is",
			uapi: head + "endpoint=198.51.100.50:51820\nallowed_ip=0.0.0.0/0\n",
			want: head + "endpoint=198.51.100.50:51820\nallowed_ip=0.0.0.0/0\n",
		},
		{
			name: "IPv6 endpoint stays as is",
			uapi: head + "endpoint=[2001:db8::1]:51820\n",
			want: head + "endpoint=[2001:db8::1]:51820\n",
		},
		{
			name:      "host name is resolved",
			uapi:      head + "endpoint=awg.example:51820\nallowed_ip=0.0.0.0/0\n",
			want:      head + "endpoint=198.51.100.50:51820\nallowed_ip=0.0.0.0/0\n",
			wantAsked: []string{"awg.example"},
		},
		{
			name:      "IPv4 is preferred when the name has both families",
			uapi:      head + "endpoint=dual.example:51820\n",
			want:      head + "endpoint=198.51.100.51:51820\n",
			wantAsked: []string{"dual.example"},
		},
		{
			name:      "IPv6-only name gets a bracketed endpoint",
			uapi:      head + "endpoint=v6.example:51820\n",
			want:      head + "endpoint=[2001:db8::6]:51820\n",
			wantAsked: []string{"v6.example"},
		},
		{
			name:      "4-in-6 answers are unmapped",
			uapi:      head + "endpoint=mapped.test:51820\n",
			want:      head + "endpoint=198.51.100.52:51820\n",
			wantAsked: []string{"mapped.test"},
		},
		{
			name:      "every peer is resolved",
			uapi:      head + "endpoint=awg.example:1\npublic_key=03\nendpoint=10.0.0.1:2\npublic_key=04\nendpoint=v6.example:3\n",
			want:      head + "endpoint=198.51.100.50:1\npublic_key=03\nendpoint=10.0.0.1:2\npublic_key=04\nendpoint=[2001:db8::6]:3\n",
			wantAsked: []string{"awg.example", "v6.example"},
		},
		{
			name:      "unknown host fails naming it",
			uapi:      head + "endpoint=nx.example:51820\n",
			wantAsked: []string{"nx.example"},
			wantErr:   "endpoint: resolve nx.example: ",
		},
		{
			name: "no endpoint at all is left alone",
			uapi: head + "allowed_ip=0.0.0.0/0\n",
			want: head + "allowed_ip=0.0.0.0/0\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeResolver{addrs: table}
			got, err := resolveEndpoints(context.Background(), r, tc.uapi)
			if tc.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want prefix %q", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if got != tc.want {
					t.Errorf("uapi =\n%s\nwant\n%s", got, tc.want)
				}
			}
			if asked := r.calls(); strings.Join(asked, ",") != strings.Join(tc.wantAsked, ",") {
				t.Errorf("looked up %v, want %v", asked, tc.wantAsked)
			}
		})
	}
}

// TestProbeEndpointResolveFailure is the failure half of decision #53 п. 1:
// a name that does not resolve fails the probe as awg_no_handshake (the
// reason dictionary is not extended), and detail says which name and why
// instead of amneziawg-go's "unable to parse IP".
func TestProbeEndpointResolveFailure(t *testing.T) {
	t.Parallel()

	cfg := confFor(t, "nx.example:51820", "")
	p := Prober{Log: silent(), Resolver: &fakeResolver{}}
	res := p.Probe(context.Background(), "https://203.0.113.7:8443/v1/probe", "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"}, cfg,
		probe.Budgets{Budget: time.Second, Connect: 100 * time.Millisecond})

	if res.Ok || deref(res.Reason) != proto.ReasonAWGNoHandshake {
		t.Fatalf("got %+v, want a failed awg_no_handshake result", res)
	}
	if d := deref(res.Detail); !strings.HasPrefix(d, "endpoint: resolve nx.example: ") {
		t.Errorf("detail = %q, want it to name the host that did not resolve", d)
	}
	if res.HandshakeMs != nil || res.ConnectMs != nil {
		t.Errorf("a probe that never built a device measured phases: %+v", res)
	}
}
