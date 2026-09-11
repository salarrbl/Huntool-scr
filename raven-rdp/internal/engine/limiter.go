package engine

import (
	"context"
	"sync"
	"time"
)

// rateWaitNotice is the wait duration after which a blocked worker
// emits a RATE_LIMITED notice for observability. The attempt itself is
// still made once the slot frees up.
const rateWaitNotice = time.Second

// RateLimiter spaces out authentication attempts against a single
// target. Multiple workers may wait on the same limiter; each granted
// slot is at least one interval apart, capping the per-target attempt
// rate.
type RateLimiter struct {
	interval time.Duration

	mu   sync.Mutex
	next time.Time
	init bool
}

// NewRateLimiter creates a limiter allowing ratePerMinute attempts per
// minute against one target.
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	if ratePerMinute < 1 {
		ratePerMinute = 1
	}
	return &RateLimiter{interval: time.Duration(float64(time.Minute) / float64(ratePerMinute))}
}

// Wait blocks until an attempt slot is granted, returning how long the
// caller waited. It returns an error only if ctx is done while waiting.
//
// The implementation uses a single reservation point (the next-slot
// timestamp) protected by a mutex, then sleeps the remainder with a
// timer — no goroutine per target, no busy loop.
func (r *RateLimiter) Wait(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	for {
		var wait time.Duration
		r.mu.Lock()
		now := time.Now()
		if !r.init || now.After(r.next) {
			r.init = true
			r.next = now.Add(r.interval)
			r.mu.Unlock()
			return time.Since(start), nil
		}
		wait = r.next.Sub(now)
		r.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			// The timer has already fired; Stop would be a no-op
			// here, so the slot re-check below just loops.
		case <-ctx.Done():
			// Stop releases the timer only on the path where it has
			// not fired yet.
			timer.Stop()
			return time.Since(start), ctx.Err()
		}
		if ctx.Err() != nil {
			return time.Since(start), ctx.Err()
		}
	}
}

// NoticeThreshold reports the wait duration after which callers should
// surface a RATE_LIMITED event.
func (r *RateLimiter) NoticeThreshold() time.Duration {
	return rateWaitNotice
}
