package clientcfg

import (
	"strings"
	"testing"
)

// orderedDocument is the document of protocol §4.2 in the field order the
// specification spells it.
const orderedDocument = `{
  "configRevision": "0000000000000000",
  "monClientId": "ams-1",
  "probeUrl": "https://203.0.113.10:443/v1/probe",
  "probe": {"intervalMs": 60000, "budgetMs": 20000, "connectMs": 5000, "tlsMs": 10000, "headersMs": 10000, "startJitterMs": 5000, "heartbeatTimeoutMs": 10000},
  "targets": [
    {"inboundKind": "xray", "inboundId": 12, "path": "proxy", "protocol": "vless", "link": "vless://uuid@front.example.net:443?security=reality&type=tcp#probe-12"},
    {"inboundKind": "awg", "inboundId": 0, "path": "proxy", "protocol": "awg", "conf": "[Interface]\nPrivateKey = KEY\n[Peer]\nEndpoint = front.example.net:51820\n"}
  ]
}`

func TestRevisionOfIgnoresHowTheDocumentIsWritten(t *testing.T) {
	want, err := RevisionOf([]byte(orderedDocument))
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}
	if len(want) != RevisionHexLen {
		t.Fatalf("revision %q is %d characters, want %d", want, len(want), RevisionHexLen)
	}
	if strings.Trim(want, "0123456789abcdef") != "" {
		t.Fatalf("revision %q is not lowercase hex", want)
	}

	tests := []struct {
		name     string
		document string
	}{
		{
			name:     "the same bytes twice",
			document: orderedDocument,
		},
		{
			name: "every key in a different order",
			document: `{
			  "targets": [
			    {"link": "vless://uuid@front.example.net:443?security=reality&type=tcp#probe-12", "protocol": "vless", "path": "proxy", "inboundId": 12, "inboundKind": "xray"},
			    {"conf": "[Interface]\nPrivateKey = KEY\n[Peer]\nEndpoint = front.example.net:51820\n", "protocol": "awg", "path": "proxy", "inboundId": 0, "inboundKind": "awg"}
			  ],
			  "probe": {"heartbeatTimeoutMs": 10000, "startJitterMs": 5000, "headersMs": 10000, "tlsMs": 10000, "connectMs": 5000, "budgetMs": 20000, "intervalMs": 60000},
			  "probeUrl": "https://203.0.113.10:443/v1/probe",
			  "monClientId": "ams-1",
			  "configRevision": "0000000000000000"
			}`,
		},
		{
			name:     "no insignificant whitespace",
			document: `{"configRevision":"0000000000000000","monClientId":"ams-1","probeUrl":"https://203.0.113.10:443/v1/probe","probe":{"intervalMs":60000,"budgetMs":20000,"connectMs":5000,"tlsMs":10000,"headersMs":10000,"startJitterMs":5000,"heartbeatTimeoutMs":10000},"targets":[{"inboundKind":"xray","inboundId":12,"path":"proxy","protocol":"vless","link":"vless://uuid@front.example.net:443?security=reality&type=tcp#probe-12"},{"inboundKind":"awg","inboundId":0,"path":"proxy","protocol":"awg","conf":"[Interface]\nPrivateKey = KEY\n[Peer]\nEndpoint = front.example.net:51820\n"}]}`,
		},
		{
			name:     "another config revision in the field the hash leaves out",
			document: strings.Replace(orderedDocument, `"0000000000000000"`, `"ffffffffffffffff"`, 1),
		},
		{
			name:     "no config revision field at all",
			document: strings.Replace(orderedDocument, `"configRevision": "0000000000000000",`, "", 1),
		},
		{
			name:     "an ampersand written as an escape",
			document: strings.Replace(orderedDocument, "&type=tcp", `&type=tcp`, 1),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RevisionOf([]byte(tc.document))
			if err != nil {
				t.Fatalf("RevisionOf: %v", err)
			}
			if got != want {
				t.Errorf("revision = %q, want %q", got, want)
			}
		})
	}
}

func TestRevisionOfSeesEveryFieldItHashes(t *testing.T) {
	base, err := RevisionOf([]byte(orderedDocument))
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}

	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "the mon-client id", old: `"ams-1"`, new: `"ams-2"`},
		{name: "the probe url", old: `:443/v1/probe`, new: `:8443/v1/probe`},
		{name: "a probe parameter", old: `"intervalMs": 60000`, new: `"intervalMs": 30000`},
		{name: "a link", old: `#probe-12`, new: `#probe-13`},
		{name: "a conf", old: `Endpoint = front.example.net:51820`, new: `Endpoint = 203.0.113.10:51820`},
		{name: "a path", old: `"path": "proxy", "protocol": "vless"`, new: `"path": "direct", "protocol": "vless"`},
		{name: "the order of the targets", old: `"inboundId": 12`, new: `"inboundId": 21`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(orderedDocument, tc.old, tc.new, 1)
			if mutated == orderedDocument {
				t.Fatalf("test is broken: %q is not in the document", tc.old)
			}
			got, err := RevisionOf([]byte(mutated))
			if err != nil {
				t.Fatalf("RevisionOf: %v", err)
			}
			if got == base {
				t.Errorf("revision did not change, still %q", got)
			}
		})
	}
}

func TestRevisionOfRejectsWhatIsNotADocument(t *testing.T) {
	if _, err := RevisionOf([]byte(`{"monClientId":`)); err == nil {
		t.Fatal("RevisionOf accepted truncated JSON")
	}
}

func TestWriteCanonicalSortsKeysAndDropsWhitespace(t *testing.T) {
	got, err := RevisionOf([]byte(`{"b":1,"a":[{"d":true,"c":null}]}`))
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}
	same, err := RevisionOf([]byte("{\n\t\"a\" : [ { \"c\" : null , \"d\" : true } ] ,\n\t\"b\" : 1\n}"))
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}
	if got != same {
		t.Errorf("canonical form depends on how the JSON was written: %q != %q", got, same)
	}
}

func TestRevisionMatchesRevisionOfTheMarshalledDocument(t *testing.T) {
	doc := Document{
		MonClientID: "ams-1",
		ProbeURL:    "https://203.0.113.10:443/v1/probe",
		Probe:       Probe{IntervalMs: 60000, BudgetMs: 20000, ConnectMs: 5000, TLSMs: 10000, HeadersMs: 10000, StartJitterMs: 5000, HeartbeatTimeoutMs: 10000},
		Targets: []DocumentTarget{{
			Target:   Target{InboundKind: "xray", InboundID: 12, Path: "proxy"},
			Protocol: "vless",
			Link:     "vless://uuid@front.example.net:443?security=reality&type=tcp#probe-12",
		}},
	}

	revision, err := Revision(doc)
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}

	// Filling the field in must not change the answer: it is the one field
	// the hash leaves out.
	doc.ConfigRevision = revision
	raw, err := marshalDocument(doc)
	if err != nil {
		t.Fatalf("marshalDocument: %v", err)
	}
	stored, err := RevisionOf(raw)
	if err != nil {
		t.Fatalf("RevisionOf: %v", err)
	}
	if stored != revision {
		t.Errorf("stored document hashes to %q, the revision written into it is %q", stored, revision)
	}
}
