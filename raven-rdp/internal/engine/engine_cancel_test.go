package engine

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/salarrbl/raven-rdp/internal/rdp"
)

// TestEngineCancelWithStuckAuth is a regression test for N2. The
// closer goroutine only woke on the trackJobEnd broadcast, and its
// ctx check ran solely on loop entry, so a run cancelled while an
// attempt was in flight parked the closer — and with it Engine.Run —
// forever. The mock below ignores ctx completely, which is exactly
// what a non-RDP service (SSH on 22, say) that answers the probe but
// never completes the handshake looks like from the worker's side.
//
// The existing TestEngineWorkerCancellation cannot catch this: its
// mock blocks on <-ctx.Done() and therefore cooperates with
// cancellation.
func TestEngineCancelWithStuckAuth(t *testing.T) {
	// stuck is closed only after Run has returned: for the duration
	// of the run the attempt is wedged.
	stuck := make(chan struct{})
	entered := make(chan struct{}, 1)

	tc := &mockClient{
		probes: func(tgt rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, tgt rdp.Target, user, pass string) rdp.AuthResult {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-stuck // never observes ctx
			return rdp.AuthResult{Status: rdp.StatusCancelled, Error: "cancelled"}
		},
	}

	baseline := runtime.NumGoroutine()

	r, err := streamTargetsForTest(newTestTargets(t, "10.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	eng := New(tc, fastPolicy(20, 2), []string{"alice"}, 3,
		func(int) string { return "x" }, testLogger())

	// Keep the event stream drained so a full buffer cannot mask a
	// hang behind backpressure.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range eng.Events() {
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, r) }()

	// Cancel only once an attempt is genuinely in flight.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("auth attempt never started")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel while an attempt was stuck")
	}

	// The auth stage must be shut down even though the job never
	// finished: this is the closer waking on ctx.Done.
	if !waitForAuthQueueClose(eng, 500*time.Millisecond) {
		t.Fatal("auth queue stayed open: the closer never woke on cancel")
	}

	// Let the wedged call unwind, then require every goroutine the
	// engine started to be gone.
	close(stuck)
	<-drained

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: baseline %d, now %d", baseline, runtime.NumGoroutine())
}

func waitForAuthQueueClose(e *Engine, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		e.authQueue.mu.RLock()
		closed := e.authQueue.closed
		e.authQueue.mu.RUnlock()
		if closed {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEngineCancelWithoutStuckWorkUnwindsFast pins the other half of
// N2: the bounded wait must not slow down a cooperative shutdown.
func TestEngineCancelWithoutStuckWorkUnwindsFast(t *testing.T) {
	tc := &mockClient{
		probes: func(tgt rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, tgt rdp.Target, user, pass string) rdp.AuthResult {
			<-ctx.Done()
			return rdp.AuthResult{Status: rdp.StatusCancelled, Error: "cancelled"}
		},
	}

	r, err := streamTargetsForTest(newTestTargets(t, "10.1.1.1", "10.1.1.2"))
	if err != nil {
		t.Fatal(err)
	}
	eng := New(tc, fastPolicy(20, 2), []string{"alice"}, 3,
		func(int) string { return "x" }, testLogger())
	go func() {
		for range eng.Events() {
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, r) }()

	time.Sleep(100 * time.Millisecond)
	cancel()

	start := time.Now()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cooperative cancel did not unwind within 2s")
	}
	if elapsed := time.Since(start); elapsed > cancelGrace {
		t.Fatalf("cooperative cancel took %v, want well under the %v grace period", elapsed, cancelGrace)
	}
}
