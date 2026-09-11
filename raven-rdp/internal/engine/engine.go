// Package engine implements the controlled worker engine: streaming
// targets flow into a bounded probe stage, open targets become
// authentication jobs in a bounded auth stage, and every outcome is
// recorded in race-free metrics and an event stream.
package engine

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/salarrbl/raven-rdp/internal/input"
	"github.com/salarrbl/raven-rdp/internal/rdp"
	"github.com/salarrbl/raven-rdp/internal/safety"
)

// eventBuffer is the engine-side event channel capacity. A single
// dispatcher consumes it and fans out to TUI/console/report writers.
const eventBuffer = 512

// queueBuffer bounds how many targets/jobs may wait in each stage.
const queueBuffer = 1024

// cancelGrace is how long a cancelled run waits for its workers to
// unwind before returning without them. Cooperative workers finish in
// microseconds; the bound exists so a client stuck inside a blocking
// call cannot hold the process open.
const cancelGrace = time.Second

// Event is one observable outcome of the audit. Passwords are never
// part of an event; only usernames (which are not secrets) appear.
type Event struct {
	Time     time.Time
	Target   string
	Status   rdp.Status
	Username string
	Message  string
	Duration time.Duration
}

// Metrics holds race-free run statistics. All counters are atomic and
// may be read at any time.
type Metrics struct {
	// N1: the start time is written by Engine.Run and read from the
	// TUI goroutine on every tick, so it must be atomic; a plain
	// time.Time field is a data race.
	start atomic.Pointer[time.Time]

	Targets     atomic.Int64 // accepted targets fed to the engine
	Completed   atomic.Int64 // targets whose lifecycle is finished
	Open        atomic.Int64
	Closed      atomic.Int64
	Timeout     atomic.Int64
	ProbeError  atomic.Int64
	SkippedAuth atomic.Int64 // open but NLA not enforced

	Attempts     atomic.Int64
	Success      atomic.Int64
	Failed       atomic.Int64
	AuthTimeout  atomic.Int64
	AuthError    atomic.Int64
	Cancelled    atomic.Int64
	RateNotices  atomic.Int64
	LimitReached atomic.Int64
}

// MarkStart records the moment the run began. It is safe to call
// concurrently with the readers below.
func (m *Metrics) MarkStart(t time.Time) { m.start.Store(&t) }

// Elapsed returns wall time since the run started. It returns 0
// before the run has been started.
func (m *Metrics) Elapsed() time.Duration {
	p := m.start.Load()
	if p == nil {
		return 0
	}
	return time.Since(*p)
}

// AttemptsPerSec returns the average attempt rate. It returns 0 only
// for effectively zero elapsed time (the first moments of a run), so
// a busy first second reports its real rate instead of a flat zero.
func (m *Metrics) AttemptsPerSec() float64 {
	elapsed := m.Elapsed().Seconds()
	if elapsed <= 0.1 {
		return 0
	}
	return float64(m.Attempts.Load()) / elapsed
}

// Remaining reports how many targets have not finished yet.
func (m *Metrics) Remaining() int64 {
	rem := m.Targets.Load() - m.Completed.Load()
	if rem < 0 {
		rem = 0
	}
	return rem
}

// pauseGate blocks new authentication work while paused; in-flight
// operations are unaffected.
type pauseGate struct {
	mu     sync.Mutex
	ch     chan struct{}
	paused bool
}

func (g *pauseGate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.ch = make(chan struct{})
}

func (g *pauseGate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		return
	}
	g.paused = false
	close(g.ch)
}

func (g *pauseGate) Paused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// Wait blocks while paused. It returns an error only when ctx is done.
func (g *pauseGate) Wait(ctx context.Context) error {
	g.mu.Lock()
	if !g.paused {
		g.mu.Unlock()
		return nil
	}
	ch := g.ch
	g.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Engine drives the two-stage audit.
type Engine struct {
	client     rdp.Client
	policy     safety.Policy
	users      []string
	passCount  int
	passwordAt func(int) string
	log        *slog.Logger

	events      chan Event
	targetQueue *Queue[rdp.Target]
	authQueue   *Queue[*Job]

	// eventsMu guards the stream close. Run can return (on cancel)
	// while a client is still wedged inside a call; that worker's
	// later emit must be a no-op, not a send on a closed channel.
	eventsMu     sync.RWMutex
	eventsClosed bool

	metrics Metrics
	gate    pauseGate

	// liveJobs counts auth jobs that are running or waiting to be
	// re-queued. The auth queue is closed only after probing has
	// ended AND liveJobs reaches zero, so no pending attempt is ever
	// dropped by an early queue close.
	mu       sync.Mutex
	liveJobs int
	jobsCond *sync.Cond
}

// New builds an engine. passwordAt must return the i-th password and
// is the only path by which secrets reach the RDP layer.
func New(client rdp.Client, policy safety.Policy, users []string, passCount int, passwordAt func(int) string, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{
		client:      client,
		policy:      policy,
		users:       users,
		passCount:   passCount,
		passwordAt:  passwordAt,
		log:         log,
		events:      make(chan Event, eventBuffer),
		targetQueue: NewQueue[rdp.Target](queueBuffer),
		authQueue:   NewQueue[*Job](queueBuffer),
	}
	e.jobsCond = sync.NewCond(&e.mu)
	return e
}

// trackJobStart records that a new auth job is alive (running or
// waiting to be re-queued).
func (e *Engine) trackJobStart() {
	e.mu.Lock()
	e.liveJobs++
	e.mu.Unlock()
}

// trackJobEnd records that a job can never resume. When no live jobs
// remain, the closer (see Run) is woken so it can shut the auth stage
// down.
func (e *Engine) trackJobEnd() {
	e.mu.Lock()
	e.liveJobs--
	if e.liveJobs == 0 {
		e.jobsCond.Broadcast()
	}
	e.mu.Unlock()
}

// Events returns the read-only event stream (closed when Run returns).
func (e *Engine) Events() <-chan Event { return e.events }

// closeEvents closes the event stream exactly once. Any emit that
// arrives after this point is dropped rather than panicking on a send
// to a closed channel, which is what a worker wedged inside a client
// call would otherwise do once Run has already returned.
func (e *Engine) closeEvents() {
	e.eventsMu.Lock()
	if !e.eventsClosed {
		e.eventsClosed = true
		close(e.events)
	}
	e.eventsMu.Unlock()
}

// Metrics exposes live statistics.
func (e *Engine) Metrics() *Metrics { return &e.metrics }

// Policy exposes the validated safety policy.
func (e *Engine) Policy() safety.Policy { return e.policy }

// Pause halts scheduling of new authentication work.
func (e *Engine) Pause() { e.gate.Pause() }

// Resume continues authentication work.
func (e *Engine) Resume() { e.gate.Resume() }

// Paused reports the current pause state.
func (e *Engine) Paused() bool { return e.gate.Paused() }

// Run executes the audit until all queued work is finished or ctx is
// cancelled. It blocks; the returned error (if any) comes from the
// target reader, not from individual target failures.
func (e *Engine) Run(ctx context.Context, reader *input.TargetReader) error {
	defer e.closeEvents()
	e.metrics.MarkStart(time.Now())

	var probeWG, authWG sync.WaitGroup

	for i := 0; i < e.policy.Workers; i++ {
		authWG.Add(1)
		go func() {
			defer authWG.Done()
			e.authWorker(ctx)
		}()
	}
	for i := 0; i < e.policy.Workers; i++ {
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			e.probeWorker(ctx)
		}()
	}

	// N2: wake the closer when the run is cancelled. jobsCond is
	// otherwise broadcast only when liveJobs reaches zero, so a
	// worker wedged inside a client call (the classic case: a
	// non-RDP service that answers the probe but never completes the
	// handshake) would park the closer forever — the ctx check in
	// the closer loop is only evaluated on loop entry, never while
	// blocked in Wait. The watcher also exits when Run returns, so a
	// run that finishes without ever being cancelled leaks nothing.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			e.mu.Lock()
			e.jobsCond.Broadcast()
			e.mu.Unlock()
		case <-watchDone:
		}
	}()

	// Close the auth stage once probing has ended and no job can
	// still resume. Closing earlier would drop re-queued jobs;
	// waiting on ctx here keeps shutdown bounded when the run is
	// cancelled mid-attempt.
	go func() {
		probeWG.Wait()
		e.mu.Lock()
		for e.liveJobs > 0 && ctx.Err() == nil {
			e.jobsCond.Wait()
		}
		e.mu.Unlock()
		e.authQueue.Close()
	}()

	feedErr := e.feedTargets(ctx, reader)

	// N2: wait for the workers off the main path. A client that
	// blocks inside Probe or Authenticate and ignores ctx must not
	// be able to hold the run — and therefore the process — open
	// forever: after cancellation the run unwinds once the grace
	// period expires, leaving the wedged call behind.
	workersDone := make(chan struct{})
	go func() {
		authWG.Wait()
		probeWG.Wait()
		close(workersDone)
	}()

	select {
	case <-workersDone:
	case <-ctx.Done():
		select {
		case <-workersDone:
		case <-time.After(cancelGrace):
			e.log.Warn("workers did not unwind after cancellation; abandoning in-flight attempts")
		}
	}

	// A cancelled run reports cancellation even if the target stream
	// itself drained cleanly.
	if err := ctx.Err(); err != nil {
		return err
	}
	return feedErr
}

// feedTargets streams parsed targets into the probe stage.
func (e *Engine) feedTargets(ctx context.Context, reader *input.TargetReader) error {
	for {
		select {
		case t, ok := <-reader.Targets:
			if !ok {
				e.targetQueue.Close()
				err := <-reader.Done
				if err != nil {
					e.log.Error("target stream failed", "error", err)
					e.emit(ctx, rdp.StatusError, "", "", "target stream: "+err.Error(), 0)
				}
				return err
			}
			e.metrics.Targets.Add(1)
			if !e.targetQueue.Enqueue(ctx, t) {
				e.targetQueue.Close()
				return ctx.Err()
			}
		case <-ctx.Done():
			e.targetQueue.Close()
			return ctx.Err()
		}
	}
}
