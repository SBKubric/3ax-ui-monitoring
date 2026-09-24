package awg

import (
	"strings"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
)

// checkConf is a .conf the parser accepts; the cases below vary one line.
const checkConf = `[Interface]
PrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
Address = 10.66.66.2/32
Jc = 4

[Peer]
PublicKey = KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkc=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.50:51820
`

func parsedConf(t *testing.T, conf string) *config.AWGConfig {
	t.Helper()
	cfg, err := config.ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v", err)
	}
	return cfg
}

// TestCheck is decision #53 п. 2's trial IpcSet: a .conf whose values the
// parser passes through verbatim but amneziawg-go refuses is caught when
// the revision is applied, not first by a probe; a host name in Endpoint
// is not a refusal, since the probe resolves it (decision #53 п. 1).
func TestCheck(t *testing.T) {
	cases := []struct {
		name    string
		conf    string
		wantErr string
	}{
		{name: "valid", conf: checkConf},
		{name: "host name endpoint", conf: strings.Replace(checkConf, "198.51.100.50:51820", "awg.example.invalid:51820", 1)},
		{name: "ipv6 host name endpoint", conf: strings.Replace(checkConf, "198.51.100.50:51820", "[2001:db8::1]:51820", 1)},
		{name: "junk count not a number", conf: strings.Replace(checkConf, "Jc = 4", "Jc = four", 1), wantErr: "jc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(parsedConf(t, tc.conf))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Check = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Check = nil, want an error about %s", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Check = %q, want it to name %s", err, tc.wantErr)
			}
		})
	}
}

func TestCheck_NilConfig(t *testing.T) {
	if err := Check(nil); err == nil {
		t.Fatal("Check(nil) = nil, want an error")
	}
}
