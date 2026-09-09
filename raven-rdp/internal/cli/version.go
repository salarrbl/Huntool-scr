package cli

import "github.com/salarrbl/raven-rdp/internal/version"

// Version returns the semantic version.
func Version() string { return version.Version }

// Info renders the --version output.
func Info() string { return version.Info() }
