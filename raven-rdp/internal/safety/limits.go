package safety

import "sync/atomic"

// Guard holds the per-target safety state for one audited target: how
// many attempts have been reserved, the attempt limit, and whether the
// target has reached a terminal state (success, limit, or
// unavailable). It is safe for concurrent use by multiple workers.
type Guard struct {
	limit    int
	attempts atomic.Int64
	terminal atomic.Bool
}

// NewGuard creates a guard for a target with the given attempt limit.
func NewGuard(limit int) *Guard {
	return &Guard{limit: limit}
}

// Limit returns the configured attempt limit.
func (g *Guard) Limit() int { return g.limit }

// Count returns the number of attempts reserved so far.
func (g *Guard) Count() int64 { return g.attempts.Load() }

// Reserve claims the next attempt slot for the target. It returns
// false once the attempt limit has been reached; callers must stop
// scheduling work for the target.
func (g *Guard) Reserve() bool {
	for {
		if g.terminal.Load() {
			return false
		}
		cur := g.attempts.Load()
		if int(cur) >= g.limit {
			return false
		}
		if g.attempts.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// Finish marks the target terminal: no further attempts will be
// reserved, even if attempts remain under the limit (e.g. after a
// successful authentication).
func (g *Guard) Finish() { g.terminal.Store(true) }

// Done reports whether the target is terminal.
func (g *Guard) Done() bool { return g.terminal.Load() }
