package heartbeat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func tempBuffer(t *testing.T) (*Buffer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cycles.json")
	b, err := OpenBuffer(path)
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	return b, path
}

func result(ok bool) []proto.Result {
	return []proto.Result{{
		TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: "proxy"},
		Ok:        ok,
	}}
}

// TestBuffer_AddAssignsSeqAndPersistsBeforeReturning is spec §6's "цикл
// добавляется до отправки": the cycle is on disk by the time Add returns,
// so a crash before the heartbeat cannot lose it.
func TestBuffer_AddAssignsSeqAndPersistsBeforeReturning(t *testing.T) {
	b, path := tempBuffer(t)

	c := add(t, b, 1757721600000, result(true))
	if c.Seq != 1 {
		t.Fatalf("first seq = %d, want 1", c.Seq)
	}
	if c.Unverified {
		t.Fatal("a fresh cycle must not be unverified")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cycles.json not written: %v", err)
	}
	var f bufferFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode cycles.json: %v", err)
	}
	if len(f.Cycles) != 1 || f.Cycles[0].Seq != 1 || f.Cycles[0].Ts != 1757721600000 {
		t.Fatalf("cycles.json = %+v, want the cycle just added", f.Cycles)
	}

	if next := add(t, b, 1757721660000, result(false)); next.Seq != 2 {
		t.Fatalf("second seq = %d, want 2", next.Seq)
	}
	if got := b.Pending(); len(got) != 2 {
		t.Fatalf("len(Pending()) = %d, want 2", len(got))
	}
}

// TestBuffer_AckDropsAcknowledgedCycles is protocol §5.3's "ackSeq
// подтверждает всё до него включительно".
func TestBuffer_AckDropsAcknowledgedCycles(t *testing.T) {
	b, _ := tempBuffer(t)
	add(t, b, 1, result(true))
	add(t, b, 2, result(true))
	third := add(t, b, 3, result(true))

	if err := b.Ack(2); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	pending := b.Pending()
	if len(pending) != 1 || pending[0].Seq != third.Seq {
		t.Fatalf("Pending() = %+v, want only seq %d", pending, third.Seq)
	}

	if err := b.Ack(third.Seq); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := b.Pending(); len(got) != 0 {
		t.Fatalf("Pending() = %+v, want empty", got)
	}
}

// TestBuffer_MarkUnverifiedFlagsEveryPendingCycle is spec §6's answer to a
// heartbeat that was never acknowledged, and it must survive a restart:
// the flag travels to mon-server, which only counts such a cycle's
// successes (protocol §5.3).
func TestBuffer_MarkUnverifiedFlagsEveryPendingCycle(t *testing.T) {
	b, path := tempBuffer(t)
	add(t, b, 1, result(true))
	add(t, b, 2, result(false))

	if err := b.MarkUnverified(); err != nil {
		t.Fatalf("MarkUnverified: %v", err)
	}
	for _, c := range b.Pending() {
		if !c.Unverified {
			t.Fatalf("cycle %d not marked unverified", c.Seq)
		}
	}

	reopened, err := OpenBuffer(path)
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	for _, c := range reopened.Pending() {
		if !c.Unverified {
			t.Fatalf("cycle %d lost its unverified flag across a restart", c.Seq)
		}
	}
}

// TestBuffer_EvictsTheOldestPastMaxCycles is spec §6's "≤ 60 циклов,
// старые вытесняются": the 61st cycle drops the 1st.
func TestBuffer_EvictsTheOldestPastMaxCycles(t *testing.T) {
	b, _ := tempBuffer(t)
	for i := range MaxCycles {
		add(t, b, int64(i), result(true))
	}
	if got := len(b.Pending()); got != MaxCycles {
		t.Fatalf("len(Pending()) = %d, want %d", got, MaxCycles)
	}

	add(t, b, int64(MaxCycles), result(true))

	pending := b.Pending()
	if len(pending) != MaxCycles {
		t.Fatalf("len(Pending()) = %d, want it capped at %d", len(pending), MaxCycles)
	}
	if pending[0].Seq != 2 {
		t.Fatalf("oldest pending seq = %d, want 2 (seq 1 evicted)", pending[0].Seq)
	}
	if last := pending[len(pending)-1]; last.Seq != MaxCycles+1 {
		t.Fatalf("newest pending seq = %d, want %d", last.Seq, MaxCycles+1)
	}
}

// TestBuffer_SeqNeverRepeatsAfterRestart is spec §6's "seq монотонный, в
// state" — including the case the naive implementation gets wrong: every
// cycle acknowledged, so the reopened buffer is empty and has nothing to
// derive the next seq from.
func TestBuffer_SeqNeverRepeatsAfterRestart(t *testing.T) {
	b, path := tempBuffer(t)
	add(t, b, 1, result(true))
	last := add(t, b, 2, result(true))
	if err := b.Ack(last.Seq); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	reopened, err := OpenBuffer(path)
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	if got := reopened.Pending(); len(got) != 0 {
		t.Fatalf("Pending() = %+v, want empty after a full ack", got)
	}
	if c := add(t, reopened, 3, result(true)); c.Seq != last.Seq+1 {
		t.Fatalf("seq after restart = %d, want %d", c.Seq, last.Seq+1)
	}
}

// TestOpenBuffer_MissingFileIsAFreshBuffer is a mon-client's first boot.
func TestOpenBuffer_MissingFileIsAFreshBuffer(t *testing.T) {
	b, err := OpenBuffer(filepath.Join(t.TempDir(), "cycles.json"))
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	if len(b.Pending()) != 0 {
		t.Fatal("a fresh buffer must be empty")
	}
	if c := add(t, b, 1, nil); c.Seq != 1 {
		t.Fatalf("first seq = %d, want 1", c.Seq)
	}
}

// TestOpenBuffer_CorruptFileIsAnError checks the buffer refuses a file it
// cannot decode rather than silently restarting seqs mon-server has
// already acknowledged; recovering from it is cmd/mon-client's decision.
func TestOpenBuffer_CorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cycles.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := OpenBuffer(path); err == nil {
		t.Fatal("OpenBuffer accepted a corrupt cycles.json")
	}
}

// TestBuffer_AddWithNoResultsEncodesAnEmptyList is spec §4.4's empty
// cycle: a box with no targets still sends a cycle, with results [] rather
// than null.
func TestBuffer_AddWithNoResultsEncodesAnEmptyList(t *testing.T) {
	b, _ := tempBuffer(t)
	c := add(t, b, 1, nil)

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	results, ok := decoded["results"].([]any)
	if !ok || results == nil {
		t.Fatalf("cycle JSON = %s, want results as an empty list", raw)
	}
}

// add is Add with its persist error asserted away: every test in this file
// writes to a temp directory that works, so a failure there is a broken
// test rather than the condition under test (TestAdd_PersistFailure covers
// the other case).
func add(t *testing.T, b *Buffer, ts int64, results []proto.Result) proto.Cycle {
	t.Helper()
	c, err := b.Add(ts, results)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return c
}

// TestAdd_PersistFailure pins Add's contract when cycles.json cannot be
// written (here: a state directory that has been made read-only, the shape
// a full disk or a botched deployment takes). The cycle is still assigned
// its seq and still buffered in memory — mon-client keeps probing and the
// next heartbeat carries it (spec §6) — but the caller is told, so the run
// loop can say so in the log.
func TestAdd_PersistFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	b, err := OpenBuffer(filepath.Join(dir, "cycles.json"))
	if err != nil {
		t.Fatalf("OpenBuffer: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	c, err := b.Add(1757721600000, result(true))
	if err == nil {
		t.Fatal("Add reported success on a read-only state directory")
	}
	if c.Seq != 1 {
		t.Errorf("cycle seq = %d, want 1 — the cycle is still buffered", c.Seq)
	}
	if got := b.Pending(); len(got) != 1 {
		t.Errorf("pending = %d cycles, want the unpersisted one", len(got))
	}
}
