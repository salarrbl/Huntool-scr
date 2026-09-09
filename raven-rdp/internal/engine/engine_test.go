package engine

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/salarrbl/raven-rdp/internal/input"
	"github.com/salarrbl/raven-rdp/internal/rdp"
	"github.com/salarrbl/raven-rdp/internal/safety"
)

// mockClient is an in-memory rdp.Client for engine tests.
type mockClient struct {
	mu        sync.Mutex
	probes    func(t rdp.Target) rdp.ProbeResult
	auth      func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult
	authCalls []authCall
}

type authCall struct {
	target rdp.Target
	user   string
	pass   string
}

func (m *mockClient) Probe(ctx context.Context, t rdp.Target) rdp.ProbeResult {
	if ctx.Err() != nil {
		return rdp.ProbeResult{Target: t, Status: rdp.StatusCancelled, Error: "cancelled"}
	}
	res := m.probes(t)
	res.Target = t
	return res
}

func (m *mockClient) Authenticate(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
	m.mu.Lock()
	m.authCalls = append(m.authCalls, authCall{t, user, pass})
	m.mu.Unlock()
	res := m.auth(ctx, t, user, pass)
	res.Target = t
	res.Username = user
	return res
}

func (m *mockClient) calls() []authCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]authCall, len(m.authCalls))
	copy(out, m.authCalls)
	return out
}

func newTestTargets(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func streamTargetsForTest(path string) (*input.TargetReader, error) {
	return input.StreamTargets(context.Background(), path, 3389)
}

type runResult struct {
	events []Event
	m      *Metrics
	err    error
}

// runEngine runs a full engine pass against the mock client and
// collects every emitted event.
func runEngine(t *testing.T, tc *mockClient, policy safety.Policy, targets []string) runResult {
	t.Helper()
	path := newTestTargets(t, targets...)

	r, err := streamTargetsForTest(path)
	if err != nil {
		t.Fatalf("stream targets: %v", err)
	}
	eng := New(tc, policy, []string{"alice", "bob"}, 3,
		func(i int) string { return "secret" + string(rune('0'+i)) },
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	eventsCh := eng.Events()
	events := make(chan Event, 256)
	go func() {
		for ev := range eventsCh {
			events <- ev
		}
		close(events)
	}()

	err = eng.Run(context.Background(), r)

	var out []Event
	for ev := range events {
		out = append(out, ev)
	}
	return runResult{events: out, m: eng.Metrics(), err: err}
}

func hasEvent(t *testing.T, events []Event, status rdp.Status, target string) bool {
	t.Helper()
	for _, ev := range events {
		if ev.Status == status && ev.Target == target {
			return true
		}
	}
	t.Fatalf("no %s event for %s in %v", status, target, events)
	return false
}

func countStatus(events []Event, status rdp.Status) int {
	n := 0
	for _, ev := range events {
		if ev.Status == status {
			n++
		}
	}
	return n
}

var fastPolicy = func(limit, workers int) safety.Policy {
	return safety.Policy{
		AttemptLimit: limit,
		TargetRate:   600_000, // 10s interval floor is 60us; fast tests
		Workers:      workers,
		Timeout:      time.Second,
	}
}

func TestEngineAuthSuccessStopsJob(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			if user == "alice" && pass == "secret0" {
				return rdp.AuthResult{Status: rdp.StatusAuthSuccess}
			}
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}
	res := runEngine(t, tc, fastPolicy(10, 2), []string{"10.1.1.1"})

	if got := countStatus(res.events, rdp.StatusAuthSuccess); got != 1 {
		t.Fatalf("got %d AUTH_SUCCESS events, want 1: %v", got, res.events)
	}
	if res.m.Success.Load() != 1 || res.m.Attempts.Load() != 1 {
		t.Fatalf("Success=%d Attempts=%d, want 1/1", res.m.Success.Load(), res.m.Attempts.Load())
	}
	if res.m.Completed.Load() != 1 {
		t.Fatalf("Completed = %d, want 1", res.m.Completed.Load())
	}
	if calls := tc.calls(); len(calls) != 1 || calls[0].pass != "secret0" {
		t.Fatalf("auth calls = %+v, want exactly the successful pair", calls)
	}
}

func TestEngineAttemptLimit(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}
	res := runEngine(t, tc, fastPolicy(3, 2), []string{"10.1.1.1"})

	if got := tc.calls(); len(got) != 3 {
		t.Fatalf("made %d auth calls, want 3 (attempt limit)", len(got))
	}
	if !hasEvent(t, res.events, rdp.StatusAttemptLimit, "10.1.1.1:3389") {
		t.Fatalf("missing ATTEMPT_LIMIT event: %v", res.events)
	}
	if res.m.LimitReached.Load() != 1 || res.m.Failed.Load() != 3 {
		t.Fatalf("LimitReached=%d Failed=%d, want 1/3", res.m.LimitReached.Load(), res.m.Failed.Load())
	}
}

func TestEngineCredentialListExhausted(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}
	// 2 users x 3 passwords = 6 pairs < limit 20.
	res := runEngine(t, tc, fastPolicy(20, 2), []string{"10.1.1.1"})

	if got := tc.calls(); len(got) != 6 {
		t.Fatalf("made %d auth calls, want 6 (matrix exhausted)", len(got))
	}
	if !hasEvent(t, res.events, rdp.StatusInfo, "10.1.1.1:3389") {
		t.Fatalf("missing exhaustion INFO event: %v", res.events)
	}
	if res.m.LimitReached.Load() != 0 {
		t.Fatalf("LimitReached = %d, want 0", res.m.LimitReached.Load())
	}
}

func TestEngineClosedTargetSkipsAuth(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusClosed, Error: "connection refused"}
		},
		auth: func(ctx context.Context, tgt rdp.Target, user, pass string) rdp.AuthResult {
			t.Error("Authenticate must not be called for a closed target")
			return rdp.AuthResult{Status: rdp.StatusError}
		},
	}
	res := runEngine(t, tc, fastPolicy(5, 2), []string{"10.1.1.1"})

	if !hasEvent(t, res.events, rdp.StatusClosed, "10.1.1.1:3389") {
		t.Fatalf("missing CLOSED event: %v", res.events)
	}
	if res.m.Attempts.Load() != 0 || res.m.Closed.Load() != 1 {
		t.Fatalf("Attempts=%d Closed=%d, want 0/1", res.m.Attempts.Load(), res.m.Closed.Load())
	}
}

func TestEngineProbeTimeout(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusTimeout, Error: "connection timeout"}
		},
		auth: nil,
	}
	res := runEngine(t, tc, fastPolicy(5, 2), []string{"10.1.1.1"})
	if !hasEvent(t, res.events, rdp.StatusTimeout, "10.1.1.1:3389") {
		t.Fatalf("missing TIMEOUT event: %v", res.events)
	}
	if res.m.Timeout.Load() != 1 {
		t.Fatalf("Timeout = %d, want 1", res.m.Timeout.Load())
	}
}

func TestEngineNLANotEnforcedSkipsAuth(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLANotEnforced, Error: "NLA not enforced"}
		},
		auth: func(ctx context.Context, tgt rdp.Target, user, pass string) rdp.AuthResult {
			t.Error("Authenticate must not be called when NLA is not enforced")
			return rdp.AuthResult{Status: rdp.StatusError}
		},
	}
	res := runEngine(t, tc, fastPolicy(5, 2), []string{"10.1.1.1"})

	if !hasEvent(t, res.events, rdp.StatusInfo, "10.1.1.1:3389") {
		t.Fatalf("missing skip INFO event: %v", res.events)
	}
	if res.m.SkippedAuth.Load() != 1 || res.m.Attempts.Load() != 0 {
		t.Fatalf("SkippedAuth=%d Attempts=%d, want 1/0", res.m.SkippedAuth.Load(), res.m.Attempts.Load())
	}
}

func TestEngineMetricsConsistency(t *testing.T) {
	statuses := map[string]rdp.ProbeResult{
		"10.1.1.1:3389": {Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"},
		"10.1.1.2:3389": {Status: rdp.StatusClosed, Error: "connection refused"},
		"10.1.1.3:3389": {Status: rdp.StatusTimeout, Error: "connection timeout"},
	}
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult { return statuses[t.String()] },
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}
	res := runEngine(t, tc, fastPolicy(1, 3), []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"})

	if res.m.Targets.Load() != 3 {
		t.Fatalf("Targets = %d, want 3", res.m.Targets.Load())
	}
	if res.m.Completed.Load() != 3 {
		t.Fatalf("Completed = %d, want 3 (every target reaches a terminal state)", res.m.Completed.Load())
	}
	if res.m.Remaining() != 0 {
		t.Fatalf("Remaining = %d, want 0", res.m.Remaining())
	}
	if res.m.Open.Load() != 1 || res.m.Closed.Load() != 1 || res.m.Timeout.Load() != 1 {
		t.Fatalf("Open=%d Closed=%d Timeout=%d, want 1/1/1",
			res.m.Open.Load(), res.m.Closed.Load(), res.m.Timeout.Load())
	}
}

func TestEngineWorkerCancellation(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			<-ctx.Done()
			return rdp.AuthResult{Status: rdp.StatusCancelled, Error: "cancelled"}
		},
	}

	path := newTestTargets(t, "10.1.1.1", "10.1.1.2:3389")
	r, err := streamTargetsForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := New(tc, fastPolicy(20, 4), []string{"alice", "bob"}, 3,
		func(i int) string { return "x" },
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, r) }()

	// Let the auth attempts start, then cancel.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run after cancel must return an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
	if eng.Metrics().Cancelled.Load() == 0 {
		t.Fatal("Cancelled metric must be > 0 after cancellation")
	}
}

func TestEnginePauseAndResume(t *testing.T) {
	// Attempts are slow enough that pause is observable: one worker,
	// 6 pairs, 30ms per attempt.
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			time.Sleep(30 * time.Millisecond)
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}

	path := newTestTargets(t, "10.1.1.1:3389")
	r, err := streamTargetsForTest(path)
	if err != nil {
		t.Fatal(err)
	}
	eng := New(tc, fastPolicy(10, 1), []string{"alice", "bob"}, 3,
		func(i int) string { return "x" },
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), r) }()

	// Wait for the first attempt to be recorded, then pause.
	deadline := time.Now().Add(5 * time.Second)
	for len(tc.calls()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	eng.Pause()
	if !eng.Paused() {
		t.Fatal("engine did not enter paused state")
	}

	// While paused, no new attempt may start (the in-flight one
	// finishes, then the worker blocks at the pause gate).
	pausedSnapshot := -1
	steady := 0
	for time.Now().Before(time.Now().Add(400 * time.Millisecond)) {
		time.Sleep(50 * time.Millisecond)
		n := len(tc.calls())
		if n == pausedSnapshot {
			steady++
		}
		pausedSnapshot = n
		if steady >= 2 {
			break
		}
	}
	nPaused := len(tc.calls())
	eng.Resume()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not finish after resume")
	}
	if got := len(tc.calls()); got != 6 {
		t.Fatalf("attempts after full run = %d, want 6 (2 users x 3 passwords); %d while paused", got, nPaused)
	}
}

func TestEngineNoPasswordInEvents(t *testing.T) {
	tc := &mockClient{
		probes: func(t rdp.Target) rdp.ProbeResult {
			return rdp.ProbeResult{Status: rdp.StatusOpen, NLA: rdp.NLARequired, Error: "NLA enforced"}
		},
		auth: func(ctx context.Context, t rdp.Target, user, pass string) rdp.AuthResult {
			return rdp.AuthResult{Status: rdp.StatusAuthFailure, Error: "invalid credentials"}
		},
	}
	res := runEngine(t, tc, fastPolicy(2, 2), []string{"10.1.1.1"})
	for _, ev := range res.events {
		joined := ev.Target + " " + ev.Username + " " + ev.Message
		if strings.Contains(joined, "secret") {
			t.Fatalf("event leaks password material: %+v", ev)
		}
	}
}
