// Package cli parses command-line flags into an app.Config.
package cli

import (
	"bytes"
	"flag"
	"fmt"

	"github.com/salarrbl/raven-rdp/internal/app"
)

// ParseResult carries parsed configuration plus meta flags.
type ParseResult struct {
	Config      app.Config
	ShowVersion bool
	ShowHelp    bool
}

// Parse parses argv (without the program name). On --help it prints
// usage and returns ok=false with a nil error.
// newFlagSet registers all flags on fs. Defaults come from app.Default.
func newFlagSet(fs *flag.FlagSet, cfg *app.Config, noTUI *bool, showVersion *bool) {
	fs.StringVar(&cfg.TargetsFile, "targets", "", "File containing authorized RDP targets")
	fs.StringVar(&cfg.UsersFile, "users", "", "Username list")
	fs.StringVar(&cfg.PasswordsFile, "passwords", "", "Password list")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "Number of concurrent workers")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "RDP port")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Connection timeout (e.g. 5s)")
	fs.IntVar(&cfg.AttemptLimit, "attempt-limit", cfg.AttemptLimit, "Maximum authentication attempts per target")
	fs.IntVar(&cfg.TargetRate, "target-rate", cfg.TargetRate, "Maximum authentication attempts per target per minute")
	fs.StringVar(&cfg.Output, "output", "", "Output report path (JSON by default; with --json --csv both .json and .csv are written)")
	fs.BoolVar(&cfg.JSON, "json", false, "Write JSON results")
	fs.BoolVar(&cfg.CSV, "csv", false, "Write CSV results")
	fs.BoolVar(noTUI, "no-tui", false, "Disable the interactive interface (line output)")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Verbose diagnostic logging")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "Minimal output (only security-relevant events)")
	fs.BoolVar(showVersion, "version", false, "Print version and exit")
}

func Parse(argv []string) (ParseResult, error) {
	fs := flag.NewFlagSet("raven-rdp", flag.ContinueOnError)
	cfg := app.Default()

	noTUI := false
	showVersion := false
	newFlagSet(fs, &cfg, &noTUI, &showVersion)

	if err := fs.Parse(argv); err != nil {
		return ParseResult{}, err
	}

	if showVersion {
		return ParseResult{ShowVersion: true}, nil
	}

	if fs.NArg() > 0 {
		return ParseResult{}, fmt.Errorf("unexpected positional argument %q (raven-rdp takes only flags)", fs.Arg(0))
	}

	cfg.TUI = !noTUI
	return ParseResult{Config: cfg}, nil
}

// Help renders the usage text.
func Help() string {
	cfg := app.Default()
	noTUI := false
	showVersion := false
	fs := flag.NewFlagSet("raven-rdp", flag.ContinueOnError)
	newFlagSet(fs, &cfg, &noTUI, &showVersion)

	var buf bytes.Buffer
	buf.WriteString(`RavenRDP — RDP Credential Auditor

An authorized RDP credential-auditing and exposure-testing tool for
systems you own or are explicitly authorized to test.

Usage:
  raven-rdp [flags]

Example:
  raven-rdp \
    --targets targets.txt \
    --users users.txt \
    --passwords passwords.txt \
    --workers 10

Flags:
`)
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	return buf.String()
}
