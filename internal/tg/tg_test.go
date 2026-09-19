package tg

import (
	"context"
	"testing"
)

// TestNop_SendReturnsNil checks that the default Notifier is a true no-op:
// mon-server must run with no bot configured (§9.4) rather than fail startup.
func TestNop_SendReturnsNil(t *testing.T) {
	if err := (Nop{}).Send(context.Background(), "hello"); err != nil {
		t.Fatalf("Nop.Send: %v", err)
	}
}

// TestRecorder_RecordsInOrder checks that a test double keeps every message a
// caller sends, in the order sent, so later steps can assert on exactly what
// mon-server would have told Telegram.
func TestRecorder_RecordsInOrder(t *testing.T) {
	r := &Recorder{}
	ctx := context.Background()

	if err := r.Send(ctx, "first"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := r.Send(ctx, "second"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	want := []string{"first", "second"}
	if len(r.Sent) != len(want) {
		t.Fatalf("Sent = %v, want %v", r.Sent, want)
	}
	for i := range want {
		if r.Sent[i] != want[i] {
			t.Fatalf("Sent[%d] = %q, want %q", i, r.Sent[i], want[i])
		}
	}
}
