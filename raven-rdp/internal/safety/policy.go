// Package safety centralizes the conservative controls that keep an
// audit from overwhelming its targets: per-target attempt limits,
// per-target rate limits, global concurrency and timeouts.
package safety

import (
	"fmt"
	"time"
)

// Policy is the validated set of safety controls for a run.
type Policy struct {
	// AttemptLimit bounds authentication attempts per target.
	AttemptLimit int

	// TargetRate bounds authentication attempts per target per minute.
	TargetRate int

	// Workers bounds global concurrent operations.
	Workers int

	// Timeout bounds every network operation.
	Timeout time.Duration
}

// Validate reports why the policy is unusable.
func (p Policy) Validate() error {
	if p.AttemptLimit <= 0 {
		return fmt.Errorf("attempt limit must be positive (got %d)", p.AttemptLimit)
	}
	if p.TargetRate <= 0 {
		return fmt.Errorf("target rate must be positive attempts/minute (got %d)", p.TargetRate)
	}
	if p.Workers <= 0 {
		return fmt.Errorf("workers must be positive (got %d)", p.Workers)
	}
	if p.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive (got %s)", p.Timeout)
	}
	return nil
}

// SlotInterval is the minimum spacing between two attempts at one
// target implied by TargetRate.
func (p Policy) SlotInterval() time.Duration {
	return time.Duration(float64(time.Minute) / float64(p.TargetRate))
}

// Summary renders the policy for the startup banner.
func (p Policy) Summary() string {
	return fmt.Sprintf(
		"attempt-limit=%d/target  target-rate=%d/min  workers=%d  timeout=%s",
		p.AttemptLimit, p.TargetRate, p.Workers, p.Timeout,
	)
}
