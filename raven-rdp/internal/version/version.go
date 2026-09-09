// Package version carries build-time version information, settable
// via -ldflags (see Makefile).
package version

import (
	"fmt"
	"runtime"
)

// Build-time variables, set via -ldflags (see Makefile).
var (
	Version = "0.1.0"
	Commit  = "dev"
	Date    = "unknown"
)

// Info renders the --version output:
//
//	RavenRDP v0.1.0 (commit abc1234, built 2026-01-01)
//	Go: go1.x
//	Platform: linux/amd64
func Info() string {
	return fmt.Sprintf("RavenRDP v%s (commit %s, built %s)\nGo: %s\nPlatform: %s/%s",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
