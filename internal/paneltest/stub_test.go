package paneltest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/paneltest"
)

// call makes one authenticated request against the stub, the way the panel
// client does, and returns the response with its body already read.
func call(t *testing.T, s *paneltest.Stub, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	return callWithToken(t, s, paneltest.DefaultToken, method, path, body)
}

func callWithToken(t *testing.T, s *paneltest.Stub, token, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, s.URL()+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, payload
}

func TestStubGivesABare404WithoutTheToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{name: "wrong token", token: "nope"},
		{name: "empty token", token: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := paneltest.NewStub(t)
			resp, body := callWithToken(t, s, tc.token, http.MethodGet, "/mon/v1/state", "")
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
			if len(body) != 0 {
				t.Errorf("body = %q, want nothing: the panel does not admit it is there", body)
			}
			if n := s.Count(paneltest.Any); n != 1 {
				t.Errorf("recorded %d requests, want 1", n)
			}
		})
	}
}

func TestStubUnknownRouteIs404(t *testing.T) {
	s := paneltest.NewStub(t)
	resp, _ := call(t, s, http.MethodGet, "/mon/v1/nope", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	resp, _ = call(t, s, http.MethodPost, "/mon/v1/state", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d for the wrong method, want 404", resp.StatusCode)
	}
}

func TestStubProbeLifecycle(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetOverride(true, "front.example.net")

	// Before the first ensure there is no probe set, so there are no configs.
	resp, body := call(t, s, http.MethodGet, "/mon/v1/probe/configs", "")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), panel.CodeProbeNotEnsured) {
		t.Fatalf("status = %d body = %s, want 409 probe_not_ensured", resp.StatusCode, body)
	}

	resp, body = call(t, s, http.MethodPost, "/mon/v1/probe/ensure", `{"monClients":[{"id":"ams-1"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ensure: status = %d body = %s", resp.StatusCode, body)
	}
	var ensured panel.ProbeEnsureResult
	if err := json.Unmarshal(body, &ensured); err != nil {
		t.Fatalf("decode ensure: %v", err)
	}
	if ensured.SubID == "" || len(ensured.Created) != 2 || ensured.Present != 2 {
		t.Errorf("ensure = %+v, want a created probe set", ensured)
	}
	if got := s.EnsureSnapshots(); len(got) != 1 || got[0][0].ID != "ams-1" {
		t.Errorf("snapshots = %+v", got)
	}
	if got := s.State(); !got.Probe.Ensured() {
		t.Errorf("state.probe = %+v, want it ensured", got.Probe)
	}

	// A second ensure creates nothing.
	_, body = call(t, s, http.MethodPost, "/mon/v1/probe/ensure", `{"monClients":[]}`)
	if err := json.Unmarshal(body, &ensured); err != nil {
		t.Fatalf("decode ensure: %v", err)
	}
	if len(ensured.Created) != 0 {
		t.Errorf("created = %+v on the second ensure, want nothing", ensured.Created)
	}

	// The proxy path renders against the override host, direct against the
	// host the caller asked for.
	_, body = call(t, s, http.MethodGet, "/mon/v1/probe/configs", "")
	var configs panel.ProbeConfigs
	if err := json.Unmarshal(body, &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if configs.Path != panel.PathProxy || !strings.Contains(configs.Items[0].Link, "front.example.net") {
		t.Errorf("proxy configs = %+v", configs)
	}
	_, body = call(t, s, http.MethodGet, "/mon/v1/probe/configs?host=real.example.net", "")
	if err := json.Unmarshal(body, &configs); err != nil {
		t.Fatalf("decode configs: %v", err)
	}
	if configs.Path != panel.PathDirect || !strings.Contains(configs.Items[0].Link, "real.example.net") {
		t.Errorf("direct configs = %+v", configs)
	}

	resp, _ = call(t, s, http.MethodDelete, "/mon/v1/probe", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: status = %d, want 204", resp.StatusCode)
	}
	if !s.ProbeDeleted() || s.State().Probe.Ensured() {
		t.Error("the probe set survived DELETE /probe")
	}
}

func TestStubPinnedConfigsCanBeStale(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetProbeSubID("k3j9")
	s.SetConfigs(panel.PathDirect, panel.ProbeConfigs{
		Revision: "an-older-revision",
		Path:     panel.PathDirect,
		Items:    []panel.ConfigItem{},
	})

	_, body := call(t, s, http.MethodGet, "/mon/v1/probe/configs?host=real.example.net", "")
	var configs panel.ProbeConfigs
	if err := json.Unmarshal(body, &configs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if configs.Revision == s.State().Revision {
		t.Errorf("revision = %q, want it stale against the state", configs.Revision)
	}
}

func TestStubForcedFailures(t *testing.T) {
	cases := []struct {
		name       string
		failure    paneltest.Failure
		wantStatus int
		wantCode   string
	}{
		{name: "not found", failure: paneltest.NotFound(), wantStatus: http.StatusNotFound},
		{name: "server error", failure: paneltest.ServerError(), wantStatus: http.StatusInternalServerError, wantCode: "internal"},
		{name: "starting", failure: paneltest.Starting(), wantStatus: http.StatusServiceUnavailable, wantCode: "starting"},
		{name: "override disabled", failure: paneltest.OverrideDisabled(), wantStatus: http.StatusConflict, wantCode: panel.CodeOverrideDisabled},
		{name: "probe not ensured", failure: paneltest.ProbeNotEnsured(), wantStatus: http.StatusConflict, wantCode: panel.CodeProbeNotEnsured},
		{name: "xray unavailable", failure: paneltest.XrayUnavailable(), wantStatus: http.StatusServiceUnavailable, wantCode: panel.CodeXrayUnavailable},
		{name: "batch too large", failure: paneltest.BatchTooLarge(), wantStatus: http.StatusRequestEntityTooLarge, wantCode: panel.CodeBatchTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := paneltest.NewStub(t)
			s.Fail(paneltest.State, tc.failure)

			resp, body := call(t, s, http.MethodGet, "/mon/v1/state", "")
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantCode == "" {
				if len(body) != 0 {
					t.Errorf("body = %q, want none", body)
				}
				return
			}
			var envelope struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if envelope.Error != tc.wantCode {
				t.Errorf("error = %q, want %q", envelope.Error, tc.wantCode)
			}
		})
	}
}

func TestStubFailureRunsOut(t *testing.T) {
	s := paneltest.NewStub(t)
	s.Fail(paneltest.Any, paneltest.ServerError().NTimes(2))

	for i := range 2 {
		if resp, _ := call(t, s, http.MethodGet, "/mon/v1/state", ""); resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("call %d: status = %d, want 500", i, resp.StatusCode)
		}
	}
	if resp, _ := call(t, s, http.MethodGet, "/mon/v1/state", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d after the failure ran out, want 200", resp.StatusCode)
	}

	s.Fail(paneltest.State, paneltest.ServerError())
	s.Clear(paneltest.State)
	if resp, _ := call(t, s, http.MethodGet, "/mon/v1/state", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d after Clear, want 200", resp.StatusCode)
	}
}

func TestStubHangEndsWithTheCaller(t *testing.T) {
	s := paneltest.NewStub(t)
	s.Fail(paneltest.State, paneltest.Hanging())

	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL()+"/mon/v1/state", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+paneltest.DefaultToken)

	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()

	// The stub holds the request until the caller gives up, which is how a
	// timeout is provoked without any test sleeping.
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the hanging request answered, want the caller's cancellation")
	}
}

func TestStubRejectsMalformedBatches(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{
			name: "panel event carrying a mon-client",
			path: "/mon/v1/events",
			body: `{"events":[{"id":"1","ts":1,"kind":"panel","monClientId":"ams-1","from":"PANEL_UP","to":"PANEL_DOWN"}]}`,
		},
		{
			name: "mon_client event carrying a target",
			path: "/mon/v1/events",
			body: `{"events":[{"id":"1","ts":1,"kind":"mon_client","monClientId":"ams-1","path":"proxy","from":"ONLINE","to":"OFFLINE"}]}`,
		},
		{
			name: "target event missing its inbound",
			path: "/mon/v1/events",
			body: `{"events":[{"id":"1","ts":1,"kind":"target","monClientId":"ams-1","from":"UP","to":"DOWN"}]}`,
		},
		{
			name: "unknown event kind",
			path: "/mon/v1/events",
			body: `{"events":[{"id":"1","ts":1,"kind":"foo","from":"UP","to":"DOWN"}]}`,
		},
		{
			name: "aggregate off the five-minute grid",
			path: "/mon/v1/stats",
			body: `{"stats":[{"monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy","bucketStart":1757721301000,"nOk":1}]}`,
		},
		{
			name: "aggregate with latency but no successes",
			path: "/mon/v1/stats",
			body: `{"stats":[{"monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy","bucketStart":1757721300000,"nOk":0,"latencyAvgMs":12}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := paneltest.NewStub(t)
			resp, body := call(t, s, http.MethodPost, tc.path, tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d body = %s, want 400", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), panel.CodeInvalidBody) {
				t.Errorf("body = %s, want invalid_body", body)
			}
		})
	}
}

func TestStubCountsDuplicatesAndUnknownInbounds(t *testing.T) {
	s := paneltest.NewStub(t)
	s.SetStrictInbounds(true)
	const batch = `{"events":[
		{"id":"a","ts":1,"kind":"target","monClientId":"ams-1","inboundKind":"xray","inboundId":12,"path":"proxy","from":"UP","to":"DOWN","reason":"tls_timeout","notified":false},
		{"id":"b","ts":2,"kind":"target","monClientId":"ams-1","inboundKind":"xray","inboundId":99,"path":"proxy","from":"UP","to":"DOWN","reason":"tls_timeout","notified":false}
	]}`

	_, body := call(t, s, http.MethodPost, "/mon/v1/events", batch)
	var result panel.EventsResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Accepted != 1 || len(result.Ignored) != 1 || result.Ignored[0].Error != panel.CodeUnknownInbound {
		t.Fatalf("result = %+v, want the unknown inbound ignored", result)
	}

	_, body = call(t, s, http.MethodPost, "/mon/v1/events", batch)
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", result.Duplicates)
	}
	if got := s.Events(); len(got) != 4 {
		t.Errorf("recorded %d events, want 4: everything posted is recorded", len(got))
	}
}

func TestStubRejectsOversizedBatches(t *testing.T) {
	s := paneltest.NewStub(t)
	var sb strings.Builder
	sb.WriteString(`{"stats":[`)
	for i := range panel.MaxStats + 1 {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"monClientId":"a","inboundKind":"xray","inboundId":1,"path":"proxy","bucketStart":300000,"nOk":0}`)
	}
	sb.WriteString(`]}`)

	resp, body := call(t, s, http.MethodPost, "/mon/v1/stats", sb.String())
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body = %s, want 413", resp.StatusCode, body)
	}
}

func TestStubRecordsConcurrently(t *testing.T) {
	s := paneltest.NewStub(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			call(t, s, http.MethodGet, "/mon/v1/state", "")
			_ = s.Requests()
			_ = s.Events()
		}()
	}
	wg.Wait()
	if n := s.Count(paneltest.State); n != 8 {
		t.Errorf("recorded %d requests, want 8", n)
	}
	s.Reset()
	if n := s.Count(paneltest.Any); n != 0 {
		t.Errorf("recorded %d requests after Reset, want 0", n)
	}
}

func TestStubServesAnyWebBasePath(t *testing.T) {
	s := paneltest.NewStub(t)
	resp, _ := call(t, s, http.MethodGet, "/xyz/mon/v1/state", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 under a webBasePath", resp.StatusCode)
	}
	if got := resp.Header.Get(panel.HeaderContract); got != "1" {
		t.Errorf("%s = %q, want 1", panel.HeaderContract, got)
	}
	if got := s.Requests()[0].Endpoint; got != paneltest.State {
		t.Errorf("endpoint = %q, want %q", got, paneltest.State)
	}
}
