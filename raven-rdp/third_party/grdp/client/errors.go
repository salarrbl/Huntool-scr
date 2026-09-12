package client

import (
	"errors"

	"github.com/x90skysn3k/grdp/core"
)

// Re-export error types and kinds from core for convenience.
type ErrorKind = core.RDPErrorKind

const (
	ErrKindNetwork  = core.ErrKindNetwork
	ErrKindTLS      = core.ErrKindTLS
	ErrKindAuth     = core.ErrKindAuth
	ErrKindProtocol = core.ErrKindProtocol
	ErrKindTimeout  = core.ErrKindTimeout
)

// Sentinel errors for use with errors.Is.
var (
	ErrAuthFailed          = errors.New("authentication failed")
	ErrNLARequired         = errors.New("NLA (CredSSP) required by server")
	ErrProtocolNegotiation = errors.New("protocol negotiation failed")
)

// NewRDPError creates a typed RDP error.
func NewRDPError(kind core.RDPErrorKind, msg string, err error) *core.RDPError {
	return &core.RDPError{Kind: kind, Message: msg, Wrapped: err}
}
