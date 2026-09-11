package engine

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/salarrbl/raven-rdp/internal/rdp"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRunJobReleasesGuardSlotOnAbort is a regression test for H2: a
// cancelled runJob must not burn the Guard slot it reserved via
// NextCredential when no attempt ever happened.
func TestRunJobReleasesGuardSlotOnAbort(t *testing.T) {
	e := New(&mockClient{
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure}
		},
	}, fastPolicy(3, 1), []string{"a"}, 1, func(int) string { return "x" }, testLogger())

	job := NewJob(rdp.Target{Host: "h", Port: 1}, 3, 60) // 1s between slots
	// Warm the limiter so runJob's Wait blocks on the next slot.
	if _, err := job.Limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan jobOutcome, 1)
	go func() { out <- e.runJob(ctx, job) }()
	time.Sleep(30 * time.Millisecond) // let runJob block in the limiter
	cancel()

	select {
	case o := <-out:
		if o != jobAborted {
			t.Fatalf("outcome = %v, want jobAborted", o)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runJob did not return after cancel")
	}
	if got := job.Guard.Count(); got != 0 {
		t.Fatalf("Guard.Count = %d, want 0 (aborted slot released)", got)
	}
	if e.Metrics().Cancelled.Load() == 0 {
		t.Fatal("Cancelled metric must be incremented on abort")
	}
}

// TestAuthWorkerReleasesJobOnEnqueueFailure is a regression test for
// H3: when a re-queue fails (queue closed), the worker must release
// the job's live slot instead of abandoning it and wedging the closer
// goroutine in Engine.Run.
func TestAuthWorkerReleasesJobOnEnqueueFailure(t *testing.T) {
	e := New(&mockClient{
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure}
		},
	}, fastPolicy(3, 1), []string{"a"}, 1, func(int) string { return "x" }, testLogger())

	job := NewJob(rdp.Target{Host: "h", Port: 1}, 3, 600_000)
	e.trackJobStart()
	if !e.authQueue.Enqueue(context.Background(), job) {
		t.Fatal("enqueue failed")
	}
	// Close the auth stage while the job is still queued: the worker
	// will run the job once, fail to re-queue, and must release it.
	e.authQueue.Close()

	e.authWorker(context.Background())

	e.mu.Lock()
	live := e.liveJobs
	e.mu.Unlock()
	if live != 0 {
		t.Fatalf("liveJobs = %d, want 0 after abandoned job", live)
	}
}

// TestEmitCountsDrops is the N7 regression test: an event that cannot
// reach the stream — because the run was cancelled or because Run had
// already closed the stream — must be accounted for rather than
// vanishing without a trace.
func TestEmitCountsDrops(t *testing.T) {
	e := New(&mockClient{
		auth: func(ctx context.Context, tgt rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure}
		},
	}, fastPolicy(3, 1), []string{"a"}, 1, func(int) string { return "x" }, testLogger())

	// A delivered event is not a drop (the stream is buffered).
	e.emit(context.Background(), rdp.StatusInfo, "h:1", "", "delivered", 0)
	if got := e.Metrics().Dropped.Load(); got != 0 {
		t.Fatalf("Dropped after a delivered event = %d, want 0", got)
	}

	// Fill the buffer with nobody reading, so a further send can only
	// block. Until then the drop is not deterministic: a cancelled
	// emit still delivers whenever the buffer has room.
	for i := 0; i < eventBuffer-1; i++ {
		e.emit(context.Background(), rdp.StatusInfo, "h:1", "", "fill", 0)
	}
	if got := e.Metrics().Dropped.Load(); got != 0 {
		t.Fatalf("Dropped while filling the buffer = %d, want 0", got)
	}

	// A cancelled run drops instead of blocking the worker.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.emit(ctx, rdp.StatusInfo, "h:1", "", "cancelled", 0)
	if got := e.Metrics().Dropped.Load(); got != 1 {
		t.Fatalf("Dropped after a cancelled emit = %d, want 1", got)
	}

	// A late emit from a worker that outlived Run must not panic, and
	// must be counted. closeEvents is idempotent.
	e.closeEvents()
	e.emit(context.Background(), rdp.StatusInfo, "h:1", "", "late", 0)
	e.closeEvents()
	if got := e.Metrics().Dropped.Load(); got != 2 {
		t.Fatalf("Dropped after an emit on a closed stream = %d, want 2", got)
	}
}
