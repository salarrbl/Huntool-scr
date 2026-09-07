//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix)

package scan

// socketBudget returns 0 (no clamp) where RLIMIT_NOFILE is not a thing: on
// Windows the socket table is not bounded by a per-process descriptor limit.
func socketBudget() int { return 0 }

// fdSoftLimit reports "unknown".
func fdSoftLimit() int { return 0 }

// isTooManyFDs always reports false off Unix.
func isTooManyFDs(err error) bool { return false }

// FDLimit reports "unknown" on this platform.
func FDLimit() int { return 0 }
