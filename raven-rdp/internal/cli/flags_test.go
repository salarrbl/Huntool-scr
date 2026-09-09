package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	dir := t.TempDir()
	res, err := Parse([]string{
		"--targets", dir + "/t.txt",
		"--users", dir + "/u.txt",
		"--passwords", dir + "/p.txt",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := res.Config
	if c.Port != 3389 {
		t.Errorf("port = %d, want 3389", c.Port)
	}
	if c.Workers != 10 {
		t.Errorf("workers = %d, want 10", c.Workers)
	}
	if c.AttemptLimit != 20 {
		t.Errorf("attempt-limit = %d, want 20", c.AttemptLimit)
	}
	if !c.TUI {
		t.Error("TUI must default to true")
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", c.Timeout)
	}
}

func TestParseAllFlags(t *testing.T) {
	res, err := Parse([]string{
		"--targets", "T", "--users", "U", "--passwords", "P",
		"--workers", "3",
		"--port", "9001",
		"--timeout", "2s",
		"--attempt-limit", "7",
		"--target-rate", "600",
		"--output", "report",
		"--json",
		"--csv",
		"--verbose",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := res.Config
	if c.TargetsFile != "T" || c.UsersFile != "U" || c.PasswordsFile != "P" {
		t.Errorf("file flags wrong: %+v", c)
	}
	if c.Workers != 3 || c.Port != 9001 || c.AttemptLimit != 7 || c.TargetRate != 600 {
		t.Errorf("numeric flags wrong: %+v", c)
	}
	if c.Timeout != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", c.Timeout)
	}
	if c.Output != "report" || !c.JSON || !c.CSV || !c.Verbose {
		t.Errorf("report/verbose flags wrong: %+v", c)
	}
}

func TestParseNoTUI(t *testing.T) {
	res, err := Parse([]string{
		"--targets", "T", "--users", "U", "--passwords", "P", "--no-tui",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.TUI {
		t.Error("--no-tui must disable the TUI")
	}
}

func TestParseVersion(t *testing.T) {
	res, err := Parse([]string{"--version"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.ShowVersion {
		t.Error("--version must set ShowVersion")
	}
}

func TestParseUnknownFlag(t *testing.T) {
	if _, err := Parse([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag must be an error")
	}
}

func TestParsePositionalArgument(t *testing.T) {
	_, err := Parse([]string{"--targets", "T", "--users", "U", "--passwords", "P", "stray"})
	if err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("err = %v, want positional-argument error", err)
	}
}

func TestHelp(t *testing.T) {
	h := Help()
	// flag.PrintDefaults renders single-dash style; parsing accepts both.
	for _, want := range []string{"Usage:", "targets", "attempt-limit", "no-tui", "authorized"} {
		if !strings.Contains(h, want) {
			t.Errorf("Help() missing %q", want)
		}
	}
}
