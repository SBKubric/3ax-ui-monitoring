package registry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

func TestApproveCreatesAMonClientKeyedByTheHashOfItsToken(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	res := submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	fake.Advance(30 * time.Second)

	approved := approve(t, reg, res.RequestID, ApproveInput{Name: "AMS 1", Region: "eu-west"})
	if approved.MonClientID != "ams-1" {
		t.Fatalf("monClientId = %q, want %q", approved.MonClientID, "ams-1")
	}

	token := issuedToken(t, reg, res.RequestID)
	row := clientRow(t, st, "ams-1")
	if row.TokenHash != store.HashToken(token) {
		t.Errorf("token_hash = %q, want the SHA-256 of the issued token", row.TokenHash)
	}
	if strings.Contains(row.TokenHash, token) || row.TokenHash == token {
		t.Error("the plaintext token is stored in mon_clients")
	}
	if !row.Enabled {
		t.Error("a freshly approved mon-client must be enabled")
	}
	if row.State != store.ClientStateNever {
		t.Errorf("state = %q, want %q", row.State, store.ClientStateNever)
	}
	if want := clock.MS(testTime.Add(30 * time.Second)); row.ApprovedAt != want {
		t.Errorf("approved_at = %d, want %d", row.ApprovedAt, want)
	}
	if row.Name != "AMS 1" || row.Region != "eu-west" {
		t.Errorf("name/region = %q/%q, want %q/%q", row.Name, row.Region, "AMS 1", "eu-west")
	}
	if row.RemoteIP != "203.0.113.5" {
		t.Errorf("remote_ip = %q, want the address the request came from", row.RemoteIP)
	}
	if row.LastHeartbeat != 0 {
		t.Errorf("last_heartbeat = %d, want 0 before the first heartbeat", row.LastHeartbeat)
	}
	paths, err := store.DecodePaths(row.Paths)
	if err != nil {
		t.Fatalf("DecodePaths: %v", err)
	}
	if strings.Join(paths, ",") != "proxy,direct" {
		t.Errorf("paths = %v, want the default set", paths)
	}

	// The request records the decision and no longer holds the plaintext.
	req := requestRow(t, st, res.RequestID)
	if req.Status != store.RequestApproved || req.MonClientID != "ams-1" {
		t.Errorf("request = %q/%q, want approved for ams-1", req.Status, req.MonClientID)
	}
	if req.ApprovedToken != "" {
		t.Error("approved_token still holds the plaintext after it was collected")
	}
}

func TestApprovePaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  string
		err   error
	}{
		{name: "the default is both", paths: nil, want: "proxy,direct"},
		{name: "proxy only", paths: []string{"proxy"}, want: "proxy"},
		{name: "direct only", paths: []string{"direct"}, want: "direct"},
		{name: "an empty set is refused", paths: []string{}, err: ErrInvalidPaths},
		{name: "an unknown path is refused", paths: []string{"tunnel"}, err: ErrInvalidPaths},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg, st, _ := newTestRegistry(t)
			res := submit(t, reg, "203.0.113.5", "7K3F9Q")

			out, err := reg.Approve(context.Background(), res.RequestID, ApproveInput{Name: "ams 1", Paths: tc.paths})
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("Approve = %v, want %v", err, tc.err)
				}
				var count int64
				if err := st.DB().Model(&store.MonClient{}).Count(&count).Error; err != nil {
					t.Fatalf("count mon-clients: %v", err)
				}
				if count != 0 {
					t.Errorf("a refused approval created %d mon-clients", count)
				}
				return
			}
			if err != nil {
				t.Fatalf("Approve: %v", err)
			}
			if got := strings.Join(out.Paths, ","); got != tc.want {
				t.Errorf("result paths = %q, want %q", got, tc.want)
			}
			paths, err := store.DecodePaths(clientRow(t, st, out.MonClientID).Paths)
			if err != nil {
				t.Fatalf("DecodePaths: %v", err)
			}
			if got := strings.Join(paths, ","); got != tc.want {
				t.Errorf("stored paths = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestApproveDerivesAUniqueIDFromTheName(t *testing.T) {
	reg, _, fake := newTestRegistry(t)

	var ids []string
	for range 3 {
		res := submit(t, reg, "203.0.113.5", "7K3F9Q")
		out := approve(t, reg, res.RequestID, ApproveInput{Name: "AMS 1"})
		ids = append(ids, out.MonClientID)
		fake.Advance(61 * time.Second)
	}
	want := []string{"ams-1", "ams-1-2", "ams-1-3"}
	for i, id := range ids {
		if id != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
}

func TestApproveKeepsALongNameInsideTheIDCap(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	name := strings.Repeat("a", 200)

	first := approve(t, reg, submit(t, reg, "203.0.113.5", "7K3F9Q").RequestID, ApproveInput{Name: name})
	fake.Advance(61 * time.Second)
	second := approve(t, reg, submit(t, reg, "203.0.113.5", "7K3F9Q").RequestID, ApproveInput{Name: name})

	if len(first.MonClientID) != maxMonClientIDLen {
		t.Errorf("first id is %d characters, want %d", len(first.MonClientID), maxMonClientIDLen)
	}
	if len(second.MonClientID) > maxMonClientIDLen {
		t.Errorf("second id is %d characters, want at most %d", len(second.MonClientID), maxMonClientIDLen)
	}
	if second.MonClientID == first.MonClientID {
		t.Fatal("the second approval reused the first id")
	}
	if !strings.HasSuffix(second.MonClientID, "-2") {
		t.Errorf("second id = %q, want it derived from the first with a -2 suffix", second.MonClientID)
	}
	if !store.ValidMonClientID(second.MonClientID) {
		t.Errorf("second id = %q, which is not a valid mon-client id", second.MonClientID)
	}
}

func TestApproveRefusesANameWithoutASlug(t *testing.T) {
	reg, st, _ := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	for _, name := range []string{"", "   ", "!!!", "Москва"} {
		if _, err := reg.Approve(context.Background(), res.RequestID, ApproveInput{Name: name}); !errors.Is(err, ErrEmptyName) {
			t.Errorf("Approve(%q) = %v, want ErrEmptyName", name, err)
		}
	}
	if got := requestRow(t, st, res.RequestID).Status; got != store.RequestPending {
		t.Errorf("status = %q, want the request still pending", got)
	}
}

func TestApproveOnlyDecidesPendingRequests(t *testing.T) {
	t.Run("unknown request", func(t *testing.T) {
		reg, _, _ := newTestRegistry(t)
		if _, err := reg.Approve(context.Background(), "nope", ApproveInput{Name: "ams 1"}); !errors.Is(err, ErrRequestNotFound) {
			t.Fatalf("Approve = %v, want ErrRequestNotFound", err)
		}
	})
	t.Run("already approved", func(t *testing.T) {
		reg, _, _ := newTestRegistry(t)
		res := submit(t, reg, "203.0.113.5", "7K3F9Q")
		approve(t, reg, res.RequestID, ApproveInput{Name: "ams 1"})
		if _, err := reg.Approve(context.Background(), res.RequestID, ApproveInput{Name: "ams 2"}); !errors.Is(err, ErrRequestNotPending) {
			t.Fatalf("second Approve = %v, want ErrRequestNotPending", err)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		reg, _, _ := newTestRegistry(t)
		res := submit(t, reg, "203.0.113.5", "7K3F9Q")
		if err := reg.Reject(context.Background(), res.RequestID); err != nil {
			t.Fatalf("Reject: %v", err)
		}
		if _, err := reg.Approve(context.Background(), res.RequestID, ApproveInput{Name: "ams 1"}); !errors.Is(err, ErrRequestNotPending) {
			t.Fatalf("Approve after Reject = %v, want ErrRequestNotPending", err)
		}
		if err := reg.Reject(context.Background(), res.RequestID); !errors.Is(err, ErrRequestNotPending) {
			t.Fatalf("second Reject = %v, want ErrRequestNotPending", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		reg, st, fake := newTestRegistry(t)
		res := submit(t, reg, "203.0.113.5", "7K3F9Q")
		fake.Advance(RequestTTL + time.Second)

		if _, err := reg.Approve(context.Background(), res.RequestID, ApproveInput{Name: "ams 1"}); !errors.Is(err, ErrRequestExpired) {
			t.Fatalf("Approve of an expired request = %v, want ErrRequestExpired", err)
		}
		if got := requestRow(t, st, res.RequestID).Status; got != store.RequestExpired {
			t.Errorf("status = %q, want %q", got, store.RequestExpired)
		}
		var count int64
		if err := st.DB().Model(&store.MonClient{}).Count(&count).Error; err != nil {
			t.Fatalf("count mon-clients: %v", err)
		}
		if count != 0 {
			t.Errorf("approving an expired request created %d mon-clients", count)
		}
	})
}

func TestApproveAsReplacementKeepsTheRegistryRowAndRevokesTheOldToken(t *testing.T) {
	reg, st, fake := newTestRegistry(t)
	ctx := context.Background()

	// A first box is approved, runs for a while and reports a few things.
	first := submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	approve(t, reg, first.RequestID, ApproveInput{Name: "AMS 1", Region: "eu-west", Paths: []string{"direct"}})
	oldToken := issuedToken(t, reg, first.RequestID)
	err := st.DB().Model(&store.MonClient{}).Where("id = ?", "ams-1").Updates(map[string]any{
		"state":             store.ClientStateOnline,
		"last_heartbeat":    clock.MS(testTime),
		"missed_heartbeats": 2,
		"applied_revision":  "abc123",
		"config_error":      "could not apply",
		"config_error_at":   clock.MS(testTime),
		"xray_version":      "1.8.4",
	}).Error
	if err != nil {
		t.Fatalf("age the mon-client: %v", err)
	}
	target := store.Target{
		MonClientID: "ams-1", InboundKind: store.InboundKindXray, InboundID: 7,
		Path: store.PathDirect, State: store.TargetUp, Since: clock.MS(testTime),
	}
	if err := st.DB().Create(&target).Error; err != nil {
		t.Fatalf("create target: %v", err)
	}

	// The box is rebuilt and files a new request, which the administrator
	// approves as its replacement.
	fake.Advance(2 * time.Hour)
	second := submitFrom(t, reg, "vps-ams-1", "203.0.113.9", "203.0.113.9")
	out, err := reg.ApproveAsReplacement(ctx, second.RequestID, "ams-1")
	if err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}
	if !out.Replacement || out.MonClientID != "ams-1" {
		t.Fatalf("result = %+v, want a replacement of ams-1", out)
	}
	if out.Name != "AMS 1" || out.Region != "eu-west" || strings.Join(out.Paths, ",") != "direct" {
		t.Errorf("result = %+v, want the existing name, region and paths", out)
	}

	newToken := issuedToken(t, reg, second.RequestID)
	if newToken == oldToken {
		t.Fatal("the replacement reissued the same token")
	}

	row := clientRow(t, st, "ams-1")
	if row.Name != "AMS 1" || row.Region != "eu-west" {
		t.Errorf("name/region = %q/%q, want them kept", row.Name, row.Region)
	}
	if paths, _ := store.DecodePaths(row.Paths); strings.Join(paths, ",") != "direct" {
		t.Errorf("paths = %v, want them kept", paths)
	}
	if row.TokenHash != store.HashToken(newToken) {
		t.Error("token_hash is not the hash of the new token")
	}
	if row.State != store.ClientStateNever {
		t.Errorf("state = %q, want %q until the first heartbeat", row.State, store.ClientStateNever)
	}
	if row.LastHeartbeat != 0 || row.MissedHeartbeats != 0 {
		t.Errorf("last_heartbeat/missed = %d/%d, want both cleared", row.LastHeartbeat, row.MissedHeartbeats)
	}
	if row.AppliedRevision != "" || row.ConfigError != "" || row.ConfigErrorAt != 0 {
		t.Errorf("applied_revision/config_error = %q/%q, want both cleared", row.AppliedRevision, row.ConfigError)
	}
	if row.RemoteIP != "203.0.113.9" {
		t.Errorf("remote_ip = %q, want the new box's address", row.RemoteIP)
	}
	if want := clock.MS(testTime.Add(2 * time.Hour)); row.ApprovedAt != want {
		t.Errorf("approved_at = %d, want %d", row.ApprovedAt, want)
	}

	// The history the replacement keeps: the targets are untouched.
	var targets []store.Target
	if err := st.DB().Where("mon_client_id = ?", "ams-1").Find(&targets).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	if len(targets) != 1 || targets[0].State != store.TargetUp {
		t.Fatalf("targets = %+v, want the existing one kept", targets)
	}

	// The old token no longer authenticates, the new one does.
	if _, err := reg.AuthenticateClient(ctx, oldToken); !errors.Is(err, api.ErrTokenRevoked) {
		t.Errorf("the old token authenticates: %v", err)
	}
	id, err := reg.AuthenticateClient(ctx, newToken)
	if err != nil {
		t.Fatalf("AuthenticateClient with the new token: %v", err)
	}
	if id.MonClientID != "ams-1" {
		t.Errorf("identity = %q, want ams-1", id.MonClientID)
	}
	// No second registry row was created.
	var count int64
	if err := st.DB().Model(&store.MonClient{}).Count(&count).Error; err != nil {
		t.Fatalf("count mon-clients: %v", err)
	}
	if count != 1 {
		t.Errorf("registry holds %d mon-clients, want 1", count)
	}
}

func TestApproveAsReplacementRefusesAnUnknownMonClient(t *testing.T) {
	reg, st, _ := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	if _, err := reg.ApproveAsReplacement(context.Background(), res.RequestID, "nope"); !errors.Is(err, ErrMonClientNotFound) {
		t.Fatalf("ApproveAsReplacement = %v, want ErrMonClientNotFound", err)
	}
	if got := requestRow(t, st, res.RequestID).Status; got != store.RequestPending {
		t.Errorf("status = %q, want the request still pending", got)
	}
}

func TestRejectMarksTheRequestRejected(t *testing.T) {
	reg, st, _ := newTestRegistry(t)
	res := submit(t, reg, "203.0.113.5", "7K3F9Q")

	if err := reg.Reject(context.Background(), res.RequestID); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	row := requestRow(t, st, res.RequestID)
	if row.Status != store.RequestRejected {
		t.Errorf("status = %q, want %q", row.Status, store.RequestRejected)
	}
	if row.ApprovedToken != "" || row.MonClientID != "" {
		t.Errorf("a rejected request carries %q/%q, want neither", row.ApprovedToken, row.MonClientID)
	}
	if err := reg.Reject(context.Background(), "nope"); !errors.Is(err, ErrRequestNotFound) {
		t.Errorf("Reject of an unknown request = %v, want ErrRequestNotFound", err)
	}
}

func TestPendingListsWaitingRequestsNewestFirst(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	ctx := context.Background()

	older := submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	fake.Advance(time.Minute)
	newer := submitFrom(t, reg, "vps-ams-2", "203.0.113.6", "203.0.113.6")
	// A decided request and an expired one are not waiting for anybody.
	fake.Advance(time.Minute)
	decided := submitFrom(t, reg, "vps-ams-3", "203.0.113.7", "203.0.113.7")
	if err := reg.Reject(ctx, decided.RequestID); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	got, err := reg.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Pending returned %d requests, want 2", len(got))
	}
	if got[0].RequestID != newer.RequestID || got[1].RequestID != older.RequestID {
		t.Errorf("order = %q, %q, want the newest first", got[0].Hostname, got[1].Hostname)
	}
	if got[0].Hostname != "vps-ams-2" || got[0].PairingCode != "7K3F9Q" || got[0].Version != "0.1.0" {
		t.Errorf("first entry = %+v, want the fields the admin UI shows", got[0])
	}
	if got[0].ExpiresAt != got[0].CreatedAt+RequestTTL.Milliseconds() {
		t.Errorf("expiresAt = %d, want created_at + 5m", got[0].ExpiresAt)
	}
	if got[0].Attempt != 1 {
		t.Errorf("attempt = %d, want the box's first request", got[0].Attempt)
	}
	if n, err := reg.PendingCount(ctx); err != nil || n != 2 {
		t.Errorf("PendingCount = %d, %v, want 2", n, err)
	}
	if len(got[0].Matches) != 0 {
		t.Errorf("matches = %+v, want none while the registry is empty", got[0].Matches)
	}

	// Everything times out: nothing is waiting any more.
	fake.Advance(RequestTTL + time.Second)
	rest, err := reg.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("Pending returned %d expired requests, want none", len(rest))
	}
	if n, err := reg.PendingCount(ctx); err != nil || n != 0 {
		t.Errorf("PendingCount = %d, %v, want 0", n, err)
	}
}

func TestPendingCountsTheAttemptsOfABox(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	ctx := context.Background()

	// The same box keeps asking: its request expires, it files a new one.
	for range 3 {
		submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
		fake.Advance(RequestTTL + time.Second)
	}
	submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	// A different box is on its first attempt.
	submitFrom(t, reg, "vps-fra-1", "203.0.113.6", "203.0.113.6")

	got, err := reg.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	attempts := map[string]int{}
	for _, req := range got {
		attempts[req.Hostname] = req.Attempt
	}
	if attempts["vps-ams-1"] != 4 {
		t.Errorf("attempt of the repeating box = %d, want 4", attempts["vps-ams-1"])
	}
	if attempts["vps-fra-1"] != 1 {
		t.Errorf("attempt of the new box = %d, want 1", attempts["vps-fra-1"])
	}
}

func TestPendingHintsAtReplacements(t *testing.T) {
	reg, _, fake := newTestRegistry(t)
	ctx := context.Background()

	// One mon-client is already registered, from a known hostname and address.
	first := submitFrom(t, reg, "vps-ams-1", "203.0.113.5", "203.0.113.5")
	approve(t, reg, first.RequestID, ApproveInput{Name: "AMS 1", Region: "eu-west"})
	fake.Advance(time.Minute)

	sameHost := submitFrom(t, reg, "vps-ams-1", "198.51.100.9", "198.51.100.9")
	sameIP := submitFrom(t, reg, "vps-fra-1", "203.0.113.5", "203.0.113.5")
	stranger := submitFrom(t, reg, "vps-fra-2", "198.51.100.10", "198.51.100.10")

	got, err := reg.Pending(ctx)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	byID := map[string]PendingRequest{}
	for _, req := range got {
		byID[req.RequestID] = req
	}

	hostMatch := byID[sameHost.RequestID].Matches
	if len(hostMatch) != 1 || hostMatch[0].MonClientID != "ams-1" || !hostMatch[0].ByHostname || hostMatch[0].ByPublicIP {
		t.Errorf("hostname match = %+v, want ams-1 by hostname only", hostMatch)
	}
	if hostMatch[0].Name != "AMS 1" || hostMatch[0].Region != "eu-west" {
		t.Errorf("hint = %+v, want the mon-client's name and region for the UI", hostMatch[0])
	}
	ipMatch := byID[sameIP.RequestID].Matches
	if len(ipMatch) != 1 || ipMatch[0].MonClientID != "ams-1" || ipMatch[0].ByHostname || !ipMatch[0].ByPublicIP {
		t.Errorf("address match = %+v, want ams-1 by public ip only", ipMatch)
	}
	if got := byID[stranger.RequestID].Matches; len(got) != 0 {
		t.Errorf("unrelated request matched %+v, want nothing", got)
	}
}
