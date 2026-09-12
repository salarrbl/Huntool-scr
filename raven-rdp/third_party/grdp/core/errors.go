package core

import "fmt"

// RDPErrorKind categorizes RDP errors for programmatic handling.
type RDPErrorKind int

const (
	ErrKindNetwork  RDPErrorKind = iota // TCP dial, DNS, connection refused
	ErrKindTLS                          // TLS handshake failures
	ErrKindAuth                         // Wrong credentials (NLA/CredSSP)
	ErrKindProtocol                     // RDP protocol negotiation failures
	ErrKindTimeout                      // Context deadline exceeded
)

func (k RDPErrorKind) String() string {
	switch k {
	case ErrKindNetwork:
		return "network"
	case ErrKindTLS:
		return "tls"
	case ErrKindAuth:
		return "auth"
	case ErrKindProtocol:
		return "protocol"
	case ErrKindTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// RDPError wraps an underlying error with a Kind for programmatic handling.
type RDPError struct {
	Kind    RDPErrorKind
	Message string
	Wrapped error
}

func (e *RDPError) Error() string {
	if e.Wrapped != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Kind, e.Message, e.Wrapped)
	}
	return fmt.Sprintf("[%s] %s", e.Kind, e.Message)
}

func (e *RDPError) Unwrap() error {
	return e.Wrapped
}
