package scan

import (
	"context"
	"sync"
	"time"
)

// limiter is a small token bucket that caps how many probes per second the
// scan issues. Two knobs bound the load a scan puts on a machine: Concurrency
// (how many sockets at once) and Rate (how many attempts per second). On a
// laptop the rate is usually the one that matters: the OS, the Wi-Fi driver
// and the home NAT gateway all cope with a few hundred connections per second,
// and dropping to, say, 150/s keeps the machine perfectly usable while still
// covering a /24 in under three minutes.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // token capacity
	tokens float64
	last   time.Time
}

func newLimiter(rate float64) *limiter {
	burst := rate / 4
	if burst < 1 {
		burst = 1
	}
	if burst > 512 {
		burst = 512 // never allow a huge initial burst after an idle pause
	}
	return &limiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// wait blocks until a probe may be issued, or until ctx is done.
func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := time.Now()
		if el := now.Sub(l.last); el > 0 {
			l.last = now
			l.tokens += el.Seconds() * l.rate
			if l.tokens > l.burst {
				l.tokens = l.burst
			}
		}
		if l.tokens >= 1 {
			l.tokens -= 1
			l.mu.Unlock()
			return nil
		}
		need := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		if need < time.Millisecond {
			need = time.Millisecond
		}
		t := time.NewTimer(need)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
