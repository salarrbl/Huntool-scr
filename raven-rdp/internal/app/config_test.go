package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempFiles(t *testing.T) (targets, users, passwords string) {
	t.Helper()
	dir := t.TempDir()
	targets = filepath.Join(dir, "targets.txt")
	users = filepath.Join(dir, "users.txt")
	passwords = filepath.Join(dir, "passwords.txt")
	for _, p := range []string{targets, users, passwords} {
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return
}

func validConfig(t *testing.T) Config {
	tg, u, p := tempFiles(t)
	return Config{
		TargetsFile:   tg,
		UsersFile:     u,
		PasswordsFile: p,
		Port:          3389,
		Workers:       4,
		Timeout:       2 * time.Second,
		AttemptLimit:  5,
		TargetRate:    60,
		TUI:           false,
	}
}

func TestValidateMissingRequired(t *testing.T) {
	c := Default()
	if err := c.Validate(); err == nil {
		t.Fatal("empty config must fail validation")
	}
}

func TestValidateMissingFile(t *testing.T) {
	c := validConfig(t)
	c.TargetsFile = filepath.Join(t.TempDir(), "nope.txt")
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want missing-file error", err)
	}
}

func TestValidateDirectoryRejected(t *testing.T) {
	c := validConfig(t)
	c.UsersFile = t.TempDir()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("err = %v, want directory error", err)
	}
}

func TestValidateNumericBounds(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"workers zero", func(c *Config) { c.Workers = 0 }},
		{"port zero", func(c *Config) { c.Port = 0 }},
		{"port too high", func(c *Config) { c.Port = 70000 }},
		{"timeout zero", func(c *Config) { c.Timeout = 0 }},
		{"attempt limit zero", func(c *Config) { c.AttemptLimit = 0 }},
		{"target rate zero", func(c *Config) { c.TargetRate = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig(t)
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestValidateReportsRequireOutput(t *testing.T) {
	c := validConfig(t)
	c.JSON = true
	c.CSV = true
	if err := c.Validate(); err == nil {
		t.Fatal("--json --csv without --output must fail")
	}
	c.Output = "/tmp/report"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateOK(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestDefaultValues(t *testing.T) {
	d := Default()
	if d.Port != 3389 {
		t.Errorf("default port = %d, want 3389", d.Port)
	}
	if d.Workers <= 0 || d.Timeout <= 0 || d.AttemptLimit <= 0 || d.TargetRate <= 0 {
		t.Errorf("defaults must be positive: %+v", d)
	}
	if !d.TUI {
		t.Error("TUI must be enabled by default")
	}
}

func TestPolicyDerivation(t *testing.T) {
	c := validConfig(t)
	c.Workers = 7
	c.Timeout = 3 * time.Second
	p := c.Policy()
	if p.Workers != 7 || p.Timeout != 3*time.Second || p.AttemptLimit != 5 || p.TargetRate != 60 {
		t.Fatalf("policy = %+v, want derived from config", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("derived policy must be valid: %v", err)
	}
}
