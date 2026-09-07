//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix)

package main

import "errors"

// setNiceness is a no-op where POSIX scheduling priorities do not exist
// (Windows). The rest of the laptop profile — bounded concurrency, chunking,
// rate limiting, per-chunk pauses — works there too.
func setNiceness(level int) error {
	if level > 0 {
		return errors.New("scheduling priorities are not supported on this platform")
	}
	return nil
}
