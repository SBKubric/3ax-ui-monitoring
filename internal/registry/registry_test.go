package registry

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testTime is where the fake clock of every test starts.
var testTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// newTestRegistry opens a registry over a real SQLite file in the test's
// temporary directory, driven by a fake clock.
func newTestRegistry(t *testing.T) (*Registry, *store.Store, *clock.Fake) {
	t.Helper()
	fake := clock.NewFake(testTime)
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(fake))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	})
	return New(st, events.New(st, alert.Discard), nil), st, fake
}

// submit files a registration request from ip and fails the test if it is
// refused.
func submit(t *testing.T, reg *Registry, ip, code string) SubmitResult {
	t.Helper()
	res, err := reg.Submit(context.Background(), SubmitRequest{
		PairingCode: code,
		Hostname:    "vps-ams-1",
		Version:     "0.1.0",
		PublicIP:    ip,
		RemoteIP:    ip,
	})
	if err != nil {
		t.Fatalf("Submit from %s: %v", ip, err)
	}
	return res
}

// submitFrom files a request with a hostname and a public address of its own.
func submitFrom(t *testing.T, reg *Registry, hostname, publicIP, remoteIP string) SubmitResult {
	t.Helper()
	res, err := reg.Submit(context.Background(), SubmitRequest{
		PairingCode: "7K3F9Q",
		Hostname:    hostname,
		Version:     "0.1.0",
		PublicIP:    publicIP,
		RemoteIP:    remoteIP,
	})
	if err != nil {
		t.Fatalf("Submit from %s: %v", remoteIP, err)
	}
	return res
}

// approve accepts a request as a new mon-client and fails the test otherwise.
func approve(t *testing.T, reg *Registry, requestID string, in ApproveInput) ApproveResult {
	t.Helper()
	res, err := reg.Approve(context.Background(), requestID, in)
	if err != nil {
		t.Fatalf("Approve %q: %v", in.Name, err)
	}
	return res
}

// poll reads a request's status and fails the test if the read errors.
func poll(t *testing.T, reg *Registry, requestID string) PollResult {
	t.Helper()
	res, err := reg.Poll(context.Background(), requestID)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return res
}

// requestRow reads one registration request straight out of the database.
func requestRow(t *testing.T, st *store.Store, requestID string) store.RegistrationRequest {
	t.Helper()
	var row store.RegistrationRequest
	if err := st.DB().Where("request_id = ?", requestID).Take(&row).Error; err != nil {
		t.Fatalf("read registration request: %v", err)
	}
	return row
}

// clientRow reads one mon-client straight out of the database.
func clientRow(t *testing.T, st *store.Store, id string) store.MonClient {
	t.Helper()
	var row store.MonClient
	if err := st.DB().Where("id = ?", id).Take(&row).Error; err != nil {
		t.Fatalf("read mon-client %s: %v", id, err)
	}
	return row
}

// issuedToken approves a request and collects the token the way a mon-client
// does, through its first poll.
func issuedToken(t *testing.T, reg *Registry, requestID string) string {
	t.Helper()
	res := poll(t, reg, requestID)
	if res.Status != store.RequestApproved {
		t.Fatalf("status = %q, want %q", res.Status, store.RequestApproved)
	}
	if res.Token == "" {
		t.Fatal("the first poll of an approved request carried no token")
	}
	return res.Token
}
