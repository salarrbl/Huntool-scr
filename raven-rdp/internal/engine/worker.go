package engine

import (
	"context"
	"time"

	"github.com/salarrbl/raven-rdp/internal/rdp"
)

// probeWorker pulls targets from the probe stage, probes each one, and
// enqueues open targets as auth jobs. One probe failure never affects
// any other target, and workers never panic the program: client
// implementations are expected to return results, not raise.
func (e *Engine) probeWorker(ctx context.Context) {
	for {
		t, ok := e.targetQueue.Dequeue(ctx)
		if !ok {
			return
		}
		res := e.client.Probe(ctx, t)
		e.recordProbe(ctx, t, res)
	}
}

func (e *Engine) recordProbe(ctx context.Context, t rdp.Target, res rdp.ProbeResult) {
	switch res.Status {
	case rdp.StatusOpen:
		e.metrics.Open.Add(1)
	case rdp.StatusClosed:
		e.metrics.Closed.Add(1)
	case rdp.StatusTimeout:
		e.metrics.Timeout.Add(1)
	case rdp.StatusError:
		e.metrics.ProbeError.Add(1)
	case rdp.StatusCancelled:
		// M4: a cancelled probe is not a probe error.
		e.metrics.Cancelled.Add(1)
	}

	if res.Status != rdp.StatusOpen {
		e.metrics.Completed.Add(1)
		e.emit(ctx, res.Status, t.String(), "", res.Error, res.Duration)
		return
	}

	switch res.NLA {
	case rdp.NLANotEnforced:
		e.metrics.SkippedAuth.Add(1)
		e.metrics.Completed.Add(1)
		e.emit(ctx, rdp.StatusInfo, t.String(), "", "NLA not enforced; credential check not applicable", res.Duration)
		return
	default:
		msg := res.Error
		if msg == "" {
			msg = "RDP service open"
		}
		e.emit(ctx, rdp.StatusOpen, t.String(), "", msg, res.Duration)
	}

	job := NewJob(t, e.policy.AttemptLimit, e.policy.TargetRate)
	e.trackJobStart()
	if !e.authQueue.Enqueue(ctx, job) {
		// Context cancelled: stop scheduling new work.
		e.trackJobEnd()
		return
	}
}

// jobOutcome reports what authWorker must do with a job after one
// runJob pass.
type jobOutcome int

// runJob outcomes.
const (
	// jobTerminal: the job can never make another attempt; its live
	// slot was already released inside runJob.
	jobTerminal jobOutcome = iota
	// jobRequeue: an attempt happened and the job may still have
	// work left; it must be re-queued.
	jobRequeue
	// jobAborted: the attempt never started (cancelled); the job is
	// dropped and its live slot must be released by the caller.
	jobAborted
)

// authWorker consumes auth jobs. Each pass performs at most one
// attempt and then re-queues the job if work remains, so a
// rate-limited target never pins a worker while other targets could
// progress.
func (e *Engine) authWorker(ctx context.Context) {
	for {
		job, ok := e.authQueue.Dequeue(ctx)
		if !ok {
			return
		}
		switch e.runJob(ctx, job) {
		case jobTerminal:
			e.metrics.Completed.Add(1)
			continue
		case jobRequeue:
			if !e.authQueue.Enqueue(ctx, job) {
				// H3: the queue is closed (run cancelled or the auth
				// stage shut down): the job can never resume, so
				// release its live slot instead of abandoning it and
				// blocking the closer forever.
				e.trackJobEnd()
				return
			}
			continue
		case jobAborted:
			e.trackJobEnd()
			return
		}
	}
}

// runJob performs one authentication attempt for the job (or reports
// why no more are possible). It returns the jobOutcome the caller
// must act on.
func (e *Engine) runJob(ctx context.Context, job *Job) jobOutcome {
	user, pass, ok := job.NextCredential(e.users, e.passCount, e.passwordAt)
	if !ok {
		e.finishJob(ctx, job)
		e.trackJobEnd()
		return jobTerminal
	}

	waited, err := job.Limiter.Wait(ctx)
	if err != nil {
		// H2: the reserved attempt slot is never used; give it back
		// so cancellation does not silently burn the attempt limit.
		job.Guard.Release()
		e.metrics.Cancelled.Add(1)
		e.emit(ctx, rdp.StatusCancelled, job.Target.String(), user, "rate wait cancelled", 0)
		return jobAborted
	}
	if waited >= job.Limiter.NoticeThreshold() {
		e.metrics.RateNotices.Add(1)
		e.emit(ctx, rdp.StatusRateLimited, job.Target.String(), user, "waiting for per-target rate slot", waited)
	}

	if err := e.gate.Wait(ctx); err != nil {
		job.Guard.Release()
		e.metrics.Cancelled.Add(1)
		e.emit(ctx, rdp.StatusCancelled, job.Target.String(), user, "stopped while paused", 0)
		return jobAborted
	}

	e.metrics.Attempts.Add(1)
	res := e.client.Authenticate(ctx, job.Target, user, pass)
	e.recordAuth(ctx, job, res)
	if job.Guard.Done() {
		e.trackJobEnd()
		return jobTerminal
	}
	return jobRequeue
}

func (e *Engine) recordAuth(ctx context.Context, job *Job, res rdp.AuthResult) {
	switch res.Status {
	case rdp.StatusAuthSuccess:
		e.metrics.Success.Add(1)
		e.log.Info("credential verified", "target", res.Target.String(), "username", res.Username)
		e.emit(ctx, rdp.StatusAuthSuccess, res.Target.String(), res.Username, "Password: [REDACTED]", res.Duration)
		job.MarkSuccess()
		job.Guard.Finish()
	case rdp.StatusAuthFailure:
		e.metrics.Failed.Add(1)
		e.emit(ctx, rdp.StatusAuthFailure, res.Target.String(), res.Username, res.Error, res.Duration)
	case rdp.StatusTimeout:
		e.metrics.AuthTimeout.Add(1)
		e.emit(ctx, rdp.StatusTimeout, res.Target.String(), res.Username, res.Error, res.Duration)
	case rdp.StatusClosed:
		e.metrics.Failed.Add(1)
		e.emit(ctx, rdp.StatusClosed, res.Target.String(), res.Username, res.Error, res.Duration)
		job.Guard.Finish() // connection lost: stop hammering a dead endpoint
	case rdp.StatusCancelled:
		e.metrics.Cancelled.Add(1)
		e.emit(ctx, rdp.StatusCancelled, res.Target.String(), res.Username, res.Error, res.Duration)
	default:
		e.metrics.AuthError.Add(1)
		e.emit(ctx, rdp.StatusError, res.Target.String(), res.Username, res.Error, res.Duration)
	}
}

// finishJob emits the terminal event for a job that can no longer
// make attempts.
func (e *Engine) finishJob(ctx context.Context, job *Job) {
	if job.Success() {
		return // success was already reported
	}
	if job.Guard.Count() >= int64(job.Guard.Limit()) {
		e.metrics.LimitReached.Add(1)
		e.emit(ctx, rdp.StatusAttemptLimit, job.Target.String(), "", "attempt limit reached", 0)
		return
	}
	e.emit(ctx, rdp.StatusInfo, job.Target.String(), "", "credential list exhausted", 0)
}

// emit appends an event to the stream. It blocks only while the event
// consumer is stalled and the run is live, which applies backpressure
// to workers instead of dropping results. When the run context is
// done, the event is dropped rather than blocking a worker forever.
func (e *Engine) emit(ctx context.Context, status rdp.Status, target, username, message string, duration time.Duration) {
	ev := Event{
		Time: time.Now(), Target: target, Status: status, Username: username,
		Message: message, Duration: duration,
	}
	select {
	case e.events <- ev:
	case <-ctx.Done():
	}
}
