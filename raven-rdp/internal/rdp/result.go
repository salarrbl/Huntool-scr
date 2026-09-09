// Package rdp defines the transport-agnostic result model for RDP
// auditing: targets, probe results, authentication results and the
// shared status vocabulary used across the application.
//
// Secrets (passwords) are deliberately absent from every type in this
// package. Results are safe to log, serialize and display.
package rdp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Status classifies the outcome of a probe or authentication attempt.
type Status string

// Result statuses.
const (
	StatusOpen         Status = "OPEN"
	StatusClosed       Status = "CLOSED"
	StatusTimeout      Status = "TIMEOUT"
	StatusAuthSuccess  Status = "AUTH_SUCCESS"
	StatusAuthFailure  Status = "AUTH_FAILURE"
	StatusRateLimited  Status = "RATE_LIMITED"
	StatusAttemptLimit Status = "ATTEMPT_LIMIT"
	StatusError        Status = "ERROR"
	StatusCancelled    Status = "CANCELLED"

	// StatusInfo marks informational events (skips, completions,
	// diagnostics) that are not probe or auth outcomes.
	StatusInfo Status = "INFO"
)

// String renders the status for display and reports.
func (s Status) String() string { return string(s) }

// Target is a normalized RDP endpoint.
type Target struct {
	Host string
	Port int
}

// Address returns the canonical dial address "host:port" (IPv6 hosts
// are bracketed).
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String is the canonical "host:port" representation.
func (t Target) String() string { return t.Address() }

// ParseTarget parses a "host" or "host:port" string into a Target,
// applying the default port when none is given. It returns an
// actionable error for malformed input.
func ParseTarget(line string, defaultPort int) (Target, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	host, portStr, err := net.SplitHostPort(line)
	if err != nil {
		// Not host:port. Either a bare host, or a bare IPv6 literal.
		if strings.Count(line, ":") == 0 {
			return Target{Host: line, Port: defaultPort}, nil
		}
		// Multiple colons without brackets: treat as bare IPv6 literal.
		if ip := net.ParseIP(line); ip != nil {
			return Target{Host: ip.String(), Port: defaultPort}, nil
		}
		// host:port with an invalid port.
		return Target{}, fmt.Errorf("failed to parse target %q: %w", line, err)
	}

	if host == "" {
		return Target{}, fmt.Errorf("failed to parse target %q: missing host", line)
	}
	if portStr == "" {
		return Target{Host: host, Port: defaultPort}, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return Target{}, fmt.Errorf("failed to parse target %q: invalid port %q", line, portStr)
	}
	if port < 1 || port > 65535 {
		return Target{}, fmt.Errorf("failed to parse target %q: port %d out of range", line, port)
	}
	return Target{Host: host, Port: port}, nil
}

// NLAStatus describes the server's Network Level Authentication mode
// as observed during a probe.
type NLAStatus int

// NLA classification.
const (
	NLAUnknown NLAStatus = iota
	NLANotEnforced
	NLARequired
	NLAHybridEx
)

// String renders the NLA classification.
func (n NLAStatus) String() string {
	switch n {
	case NLANotEnforced:
		return "nla-not-enforced"
	case NLARequired:
		return "nla-required"
	case NLAHybridEx:
		return "nla-hybrid-ex"
	default:
		return "nla-unknown"
	}
}

// ProbeResult reports whether the RDP service on a target is reachable.
type ProbeResult struct {
	Target   Target
	Status   Status
	NLA      NLAStatus
	Duration time.Duration
	Error    string
}

// AuthResult reports the outcome of one authentication attempt.
//
// It intentionally carries no password or equivalent secret.
type AuthResult struct {
	Target   Target
	Username string
	Status   Status
	Duration time.Duration
	Error    string
}
