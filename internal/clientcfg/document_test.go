package clientcfg

import (
	"strings"
	"testing"
)

func TestProbeURL(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		publicIP string
		want     string
	}{
		{
			name:     "the default listener writes its port out in full",
			listen:   ":443",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:443/v1/probe",
		},
		{
			name:     "a plain port",
			listen:   ":8443",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:8443/v1/probe",
		},
		{
			name:     "the listen host is ignored, the public IP is the address",
			listen:   "0.0.0.0:8443",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:8443/v1/probe",
		},
		{
			name:     "an IPv6 public IP is bracketed",
			listen:   ":443",
			publicIP: "2001:db8::1",
			want:     "https://[2001:db8::1]:443/v1/probe",
		},
		{
			name:     "an already bracketed IPv6 public IP is not bracketed twice",
			listen:   ":8443",
			publicIP: "[2001:db8::1]",
			want:     "https://[2001:db8::1]:8443/v1/probe",
		},
		{
			name:     "an IPv6 listen address still yields its port",
			listen:   "[::]:443",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:443/v1/probe",
		},
		{
			name:     "a listen address without a port falls back to 443",
			listen:   "",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:443/v1/probe",
		},
		{
			name:     "a bare port number is accepted",
			listen:   "8443",
			publicIP: "203.0.113.10",
			want:     "https://203.0.113.10:8443/v1/probe",
		},
		{
			name:     "surrounding whitespace is ignored",
			listen:   " :8443 ",
			publicIP: " 203.0.113.10 ",
			want:     "https://203.0.113.10:8443/v1/probe",
		},
		{
			name:     "without a public address there is no probe url",
			listen:   ":443",
			publicIP: "",
			want:     "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProbeURL(tc.listen, tc.publicIP); got != tc.want {
				t.Errorf("ProbeURL(%q, %q) = %q, want %q", tc.listen, tc.publicIP, got, tc.want)
			}
		})
	}
}

func TestMarshalDocumentKeepsLinksUnescapedAndTargetsNonNull(t *testing.T) {
	const link = "vless://uuid@front.example.net:443?security=reality&type=tcp&sni=a.example<b#probe-12"

	raw, err := marshalDocument(Document{
		ConfigRevision: "0123456789abcdef",
		MonClientID:    "ams-1",
		ProbeURL:       "https://203.0.113.10:443/v1/probe",
		Targets: []DocumentTarget{{
			Target:   Target{InboundKind: "xray", InboundID: 12, Path: "proxy"},
			Protocol: "vless",
			Link:     link,
		}},
	})
	if err != nil {
		t.Fatalf("marshalDocument: %v", err)
	}
	if got := string(raw); !strings.Contains(got, link) {
		t.Errorf("document does not carry the link verbatim:\n%s", got)
	}
	if got := string(raw); strings.Contains(got, "\\u0026") || strings.Contains(got, "\\u003c") {
		t.Errorf("document escapes characters JSON does not require:\n%s", got)
	}

	empty, err := marshalDocument(Document{MonClientID: "ams-1"})
	if err != nil {
		t.Fatalf("marshalDocument: %v", err)
	}
	if got := string(empty); !strings.Contains(got, `"targets":[]`) {
		t.Errorf("a mon-client with nothing to probe must be told so with an empty array, got:\n%s", got)
	}
}
