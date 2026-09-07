//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package scan

import (
	"errors"
	"syscall"
)

// fdSoftLimit returns the process soft RLIMIT_NOFILE, or 0 when it cannot be
// read. Note that the Go runtime already raises the soft limit to the hard one
// at startup (see src/syscall/rlimit.go), so what we read here is usually the
// machine's real ceiling: 256 is still the stock hard limit in a macOS shell.
func fdSoftLimit() int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	cur := int(rl.Cur)
	if cur < 0 { // overflow on 32-bit builds with an "infinite" limit
		return 0
	}
	return cur
}

// socketBudget returns how many concurrent probes the scan may keep open at
// once: a fraction of the descriptor limit, leaving room for the output files,
// the report and everything else a process holds. 0 means "no clamp".
//
// Without this, a laptop with a small ulimit turns every attempt past the limit
// into EMFILE: the scan reports a wall of "other" and no hosts. Clamping costs
// a little throughput and keeps the result honest.
func socketBudget() int {
	soft := fdSoftLimit()
	if soft <= 0 || soft > 1<<16 {
		return 0
	}
	budget := soft*8/10 - 8
	if budget < 16 {
		budget = 16
	}
	return budget
}

// isTooManyFDs reports whether an error came from exhausting the descriptor
// table: the classic "scanner on a laptop with ulimit -n 256" failure mode.
func isTooManyFDs(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// FDLimit reports the file-descriptor soft limit in effect (0 = unknown). The
// CLI uses it for the one-line hint that tells the operator to raise ulimit for
// faster scans.
func FDLimit() int { return fdSoftLimit() }
