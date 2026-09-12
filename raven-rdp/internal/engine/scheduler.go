package engine

import (
	"sync"

	"github.com/salarrbl/raven-rdp/internal/rdp"
	"github.com/salarrbl/raven-rdp/internal/safety"
)

// Job is the scheduling state for one open target: its safety guard,
// its rate limiter, and the cursor through the credential matrix.
//
// The credential matrix (users x passwords) is never materialized: a
// job only stores its (userIdx, passIdx) cursor and pulls the next
// password through an accessor, so memory stays O(open targets)
// regardless of list sizes.
type Job struct {
	Target  rdp.Target
	Guard   *safety.Guard
	Limiter *RateLimiter

	mu       sync.Mutex
	userIdx  int
	passIdx  int
	success  bool
	finished bool
}

// NewJob creates the scheduling state for an open target.
func NewJob(t rdp.Target, attemptLimit, targetRate int) *Job {
	return &Job{
		Target:  t,
		Guard:   safety.NewGuard(attemptLimit),
		Limiter: NewRateLimiter(targetRate),
	}
}

// Success reports whether a valid credential was found.
func (j *Job) Success() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.success
}

// MarkSuccess records a verified credential (terminal for the job).
func (j *Job) MarkSuccess() {
	j.mu.Lock()
	j.success = true
	j.finished = true
	j.mu.Unlock()
}

// NextCredential returns the next (username, password) pair in
// password-major order (orthogonal pairing), reserving an attempt slot.
// It returns ok=false when the job is finished, the attempt limit is reached,
// or the credential matrix is exhausted.
//
// passwordAt is the only channel through which passwords are passed; jobs
// never store them.
func (j *Job) NextCredential(users []string, passCount int, passwordAt func(int) string) (string, string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.finished {
		return "", "", false
	}
	if !j.Guard.Reserve() {
		j.finished = true
		return "", "", false
	}
	if len(users) == 0 || passCount == 0 {
		j.finished = true
		return "", "", false
	}

	for j.passIdx < passCount {
		if j.userIdx < len(users) {
			user := users[j.userIdx]
			pass := passwordAt(j.passIdx)
			j.userIdx++
			return user, pass, true
		}
		j.userIdx = 0
		j.passIdx++
	}
	j.finished = true
	return "", "", false
}
