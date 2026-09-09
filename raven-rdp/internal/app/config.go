// Package app wires configuration, input, engine, output and the TUI
// into the application lifecycle, including graceful shutdown.
package app

import (
	"fmt"
	"os"
	"time"

	"github.com/salarrbl/raven-rdp/internal/safety"
)

// Config is the validated run configuration assembled from CLI flags.
type Config struct {
	TargetsFile   string
	UsersFile     string
	PasswordsFile string
	Port          int
	Workers       int
	Timeout       time.Duration
	AttemptLimit  int
	TargetRate    int
	Output        string
	JSON          bool
	CSV           bool
	TUI           bool
	Verbose       bool
	Quiet         bool
}

// Default returns the built-in defaults before flags are applied.
func Default() Config {
	return Config{
		Port:         3389,
		Workers:      10,
		Timeout:      5 * time.Second,
		AttemptLimit: 20,
		TargetRate:   10,
		TUI:          true,
	}
}

// Validate checks every field and the referenced input files. Errors
// are actionable and named after the offending flag.
func (c Config) Validate() error {
	if c.TargetsFile == "" {
		return fmt.Errorf("--targets is required")
	}
	if c.UsersFile == "" {
		return fmt.Errorf("--users is required")
	}
	if c.PasswordsFile == "" {
		return fmt.Errorf("--passwords is required")
	}
	for _, p := range []struct {
		flag string
		path string
	}{
		{"--targets", c.TargetsFile},
		{"--users", c.UsersFile},
		{"--passwords", c.PasswordsFile},
	} {
		st, err := os.Stat(p.path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%s: file %q does not exist", p.flag, p.path)
			}
			return fmt.Errorf("%s: cannot stat %q: %w", p.flag, p.path, err)
		}
		if st.IsDir() {
			return fmt.Errorf("%s: %q is a directory, expected a file", p.flag, p.path)
		}
	}

	if c.Workers <= 0 {
		return fmt.Errorf("--workers must be a positive integer (got %d)", c.Workers)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535 (got %d)", c.Port)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("--timeout must be a positive duration (got %s)", c.Timeout)
	}
	if c.AttemptLimit <= 0 {
		return fmt.Errorf("--attempt-limit must be a positive integer (got %d)", c.AttemptLimit)
	}
	if c.TargetRate <= 0 {
		return fmt.Errorf("--target-rate must be a positive attempts-per-minute (got %d)", c.TargetRate)
	}
	if c.JSON && c.CSV && c.Output == "" {
		return fmt.Errorf("--output is required when writing reports")
	}
	return nil
}

// Policy derives the engine safety policy from the config.
func (c Config) Policy() safety.Policy {
	return safety.Policy{
		AttemptLimit: c.AttemptLimit,
		TargetRate:   c.TargetRate,
		Workers:      c.Workers,
		Timeout:      c.Timeout,
	}
}
